//go:build windows

// This file implements user-only PATH changes through the Windows environment registry.
// 本文件通过 Windows 环境注册表实现仅限用户范围的 PATH 变更。
// The registry and broadcast boundaries are injectable so tests never need the real HKCU key.
// 注册表与广播边界可注入，因此测试不需要触碰真实 HKCU 键。
package pathctl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/OpenVulcan/vulcan-memory-mesh-manager/internal/state"
)

const (
	// windowsPathMaxUTF16Units follows the Windows environment block PATH limit.
	// windowsPathMaxUTF16Units 遵循 Windows 环境块对 PATH 的长度限制。
	windowsPathMaxUTF16Units = 32767

	// registryValueString and registryValueExpandString are the supported PATH registry types.
	// registryValueString 与 registryValueExpandString 是 PATH 支持的注册表类型。
	registryValueString       uint32 = 1
	registryValueExpandString uint32 = 2

	// registryQueryValue and registrySetValue are the minimum access rights for HKCU PATH.
	// registryQueryValue 与 registrySetValue 是访问 HKCU PATH 所需的最小权限。
	registryQueryValue uint32 = 0x0001
	registrySetValue   uint32 = 0x0002

	// currentUserHandle identifies HKEY_CURRENT_USER without elevating to machine scope.
	// currentUserHandle 标识 HKEY_CURRENT_USER，不会提升到系统范围。
	currentUserHandle syscall.Handle = 0x80000001
)

var (
	// regSetValueExW is resolved lazily so package import never mutates registry state.
	// regSetValueExW 延迟解析，确保导入包不会修改注册表状态。
	regSetValueExW = syscall.NewLazyDLL("advapi32.dll").NewProc("RegSetValueExW")

	// sendMessageTimeoutW broadcasts environment updates without waiting forever on a hung window.
	// sendMessageTimeoutW 广播环境更新，并避免无限等待无响应窗口。
	sendMessageTimeoutW = syscall.NewLazyDLL("user32.dll").NewProc("SendMessageTimeoutW")
)

// registryValue contains the exact raw PATH value and registry type observed before a change.
// registryValue 包含变更前观察到的 PATH 原始值与注册表类型。
type registryValue struct {
	// Value is the raw semicolon-separated PATH string.
	// Value 是原始分号分隔 PATH 字符串。
	Value string

	// Type is REG_SZ or REG_EXPAND_SZ for the PATH value.
	// Type 是 PATH 值使用的 REG_SZ 或 REG_EXPAND_SZ 类型。
	Type uint32

	// Present distinguishes an absent registry value from an empty present value.
	// Present 区分缺失的注册表值与存在但为空的值。
	Present bool
}

// registryBackend abstracts HKCU Environment access for deterministic tests.
// registryBackend 抽象 HKCU Environment 访问，供确定性测试注入。
type registryBackend interface {
	// ReadPath reads the current user's raw PATH value.
	// ReadPath 读取当前用户的原始 PATH 值。
	ReadPath() (registryValue, error)

	// SetPath writes a PATH value while preserving its registry type.
	// SetPath 写入 PATH 值并保留注册表类型。
	SetPath(value string, valueType uint32) error

	// DeletePath removes the user PATH value when it was absent before installation.
	// DeletePath 在安装前值不存在时删除用户 PATH 值。
	DeletePath() error
}

// environmentBroadcaster publishes the Windows environment-change notification.
// environmentBroadcaster 发布 Windows 环境变更通知。
type environmentBroadcaster interface {
	// Broadcast sends WM_SETTINGCHANGE for the Environment section.
	// Broadcast 为 Environment 区域发送 WM_SETTINGCHANGE。
	Broadcast() error
}

// Controller applies and reverses user-level Windows PATH integration.
// Controller 执行和撤销用户级 Windows PATH 集成。
type Controller struct {
	// registry is the user-scope registry backend.
	// registry 是用户范围注册表后端。
	registry registryBackend

	// broadcaster notifies already-running processes that future processes see new PATH.
	// broadcaster 通知已有进程，使后续进程读取新的 PATH。
	broadcaster environmentBroadcaster
}

// New returns a controller backed by HKCU Environment and WM_SETTINGCHANGE.
// New 返回使用 HKCU Environment 与 WM_SETTINGCHANGE 的控制器。
func New() *Controller {
	return &Controller{
		registry:    windowsRegistry{},
		broadcaster: windowsEnvironmentBroadcaster{},
	}
}

// newController creates an injectable controller for package-local tests.
// newController 创建供包内测试使用的可注入控制器。
func newController(registry registryBackend, broadcaster environmentBroadcaster) *Controller {
	return &Controller{registry: registry, broadcaster: broadcaster}
}

// Install adds one manager directory to the current user's PATH without elevation.
// Install 在不提权的情况下将一个管理器目录加入当前用户 PATH。
func (c *Controller) Install(options Options) (Record, error) {
	if c == nil || c.registry == nil || c.broadcaster == nil {
		return Record{}, errors.New("path controller is not initialized")
	}
	if options.Method == "" {
		options.Method = MethodWindowsUserPath
	}
	if options.Method != MethodWindowsUserPath {
		return Record{}, fmt.Errorf("method %q is not supported on Windows", options.Method)
	}
	if err := validateOptions(options); err != nil {
		return Record{}, fmt.Errorf("validate Windows PATH options: %w", err)
	}
	if strings.ContainsRune(options.Directory, ';') {
		return Record{}, errors.New("manager directory must not contain the Windows PATH separator")
	}
	if err := requireDirectory(options.Directory); err != nil {
		return Record{}, err
	}

	current, err := c.registry.ReadPath()
	if err != nil {
		return Record{}, fmt.Errorf("read current-user PATH: %w", err)
	}
	if current.Type != 0 && current.Type != registryValueString && current.Type != registryValueExpandString {
		return Record{}, fmt.Errorf("unsupported current-user PATH registry type %d", current.Type)
	}
	valueType := current.Type
	if valueType == 0 {
		valueType = registryValueExpandString
	}

	entries, err := splitWindowsPath(current.Value)
	if err != nil {
		return Record{}, fmt.Errorf("inspect current-user PATH: %w", err)
	}
	normalizedDirectory := normalizeWindowsPath(options.Directory)
	matches := 0
	for _, entry := range entries {
		if normalizeWindowsPath(entry) == normalizedDirectory {
			matches++
		}
	}
	if matches > 1 {
		return Record{}, fmt.Errorf("%w: directory occurs %d times in current-user PATH", ErrConflict, matches)
	}
	if matches == 1 {
		return externalRecord(MethodWindowsUserPath, options.Directory, options.Directory)
	}

	newValue := options.Directory
	if current.Value != "" {
		newValue = current.Value + ";" + options.Directory
	}
	if utf16Length(newValue) > windowsPathMaxUTF16Units {
		return Record{}, fmt.Errorf("current-user PATH exceeds the Windows %d UTF-16-unit limit", windowsPathMaxUTF16Units)
	}
	if err := c.registry.SetPath(newValue, valueType); err != nil {
		return Record{}, fmt.Errorf("write current-user PATH: %w", err)
	}
	if err := c.broadcaster.Broadcast(); err != nil {
		if rollbackErr := restoreRegistryValue(c.registry, current); rollbackErr != nil {
			return Record{}, fmt.Errorf("broadcast current-user PATH change: %w; rollback failed: %v", err, rollbackErr)
		}
		return Record{}, fmt.Errorf("broadcast current-user PATH change: %w", err)
	}

	record := Record{
		Version:     RecordVersion,
		Path:        state.PATHState{Owner: state.PATHOwnerManager, Scope: state.PATHScopeUser, Entries: []string{filepath.Clean(options.Directory)}},
		Method:      MethodWindowsUserPath,
		Directory:   filepath.Clean(options.Directory),
		AfterSHA256: digest([]byte(newValue)),
		AfterType:   valueType,
	}
	return record, nil
}

// Remove reverses only an unchanged manager-owned Windows PATH mutation.
// Remove 只撤销未被用户改动的管理器 Windows PATH 变更。
func (c *Controller) Remove(record Record) error {
	if c == nil || c.registry == nil || c.broadcaster == nil {
		return errors.New("path controller is not initialized")
	}
	if err := record.Validate(); err != nil {
		return fmt.Errorf("validate Windows PATH record: %w", err)
	}
	if record.Method != MethodWindowsUserPath {
		return fmt.Errorf("path method %q is not supported on Windows", record.Method)
	}
	if record.Path.Owner == state.PATHOwnerExternal {
		return nil
	}

	current, err := c.registry.ReadPath()
	if err != nil {
		return fmt.Errorf("read current-user PATH: %w", err)
	}
	if !current.Present {
		return nil
	}
	entries, err := splitWindowsPath(current.Value)
	if err != nil {
		return fmt.Errorf("inspect current-user PATH: %w", err)
	}
	normalizedDirectory := normalizeWindowsPath(record.Directory)
	matchIndexes := make([]int, 0, 1)
	for index, entry := range entries {
		if normalizeWindowsPath(entry) == normalizedDirectory {
			matchIndexes = append(matchIndexes, index)
		}
	}
	if len(matchIndexes) == 0 {
		return nil
	}
	if len(matchIndexes) != 1 {
		return fmt.Errorf("%w: manager directory occurs %d times in current-user PATH", ErrConflict, len(matchIndexes))
	}
	if digest([]byte(current.Value)) != record.AfterSHA256 {
		return fmt.Errorf("%w: current-user PATH differs from the recorded post-install value", ErrChanged)
	}
	if current.Type != record.AfterType {
		return fmt.Errorf("%w: current-user PATH registry type differs from the recorded post-install value", ErrChanged)
	}

	indexToRemove := matchIndexes[0]
	remaining := make([]string, 0, len(entries)-1)
	remaining = append(remaining, entries[:indexToRemove]...)
	remaining = append(remaining, entries[indexToRemove+1:]...)
	newValue := strings.Join(remaining, ";")
	if err := c.registry.SetPath(newValue, current.Type); err != nil {
		return fmt.Errorf("remove manager directory from current-user PATH: %w", err)
	}
	if err := c.broadcaster.Broadcast(); err != nil {
		if rollbackErr := c.registry.SetPath(current.Value, current.Type); rollbackErr != nil {
			return fmt.Errorf("broadcast current-user PATH removal: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("broadcast current-user PATH removal: %w", err)
	}
	return nil
}

// externalRecord returns a non-owning record for a pre-existing user entry.
// externalRecord 为安装前已经存在的用户条目返回非所有者记录。
func externalRecord(method Method, directory string, entry string) (Record, error) {
	record := Record{
		Version:   RecordVersion,
		Path:      state.PATHState{Owner: state.PATHOwnerExternal, Scope: state.PATHScopeUser, Entries: []string{filepath.Clean(entry)}},
		Method:    method,
		Directory: filepath.Clean(directory),
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// requireDirectory ensures a PATH entry names an existing directory controlled by the installer.
// requireDirectory 确保 PATH 条目指向安装器实际控制的现有目录。
func requireDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat manager directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("manager PATH entry is not a directory")
	}
	return nil
}

// splitWindowsPath validates PATH segments while preserving their original ordering and spelling.
// splitWindowsPath 校验 PATH 片段，同时保留原始顺序和拼写以便精确写回。
func splitWindowsPath(value string) ([]string, error) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return nil, errors.New("current-user PATH contains a control character")
	}
	return strings.Split(value, ";"), nil
}

// normalizeWindowsPath compares absolute PATH directories without changing the stored value.
// normalizeWindowsPath 只用于比较绝对 PATH 目录，不会改写储存的原值。
func normalizeWindowsPath(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, `"`)
	trimmed = strings.TrimSuffix(trimmed, `"`)
	return strings.ToLower(filepath.Clean(trimmed))
}

// utf16Length counts Windows environment characters rather than UTF-8 bytes.
// utf16Length 计算 Windows 环境字符数，而不是 UTF-8 字节数。
func utf16Length(value string) int {
	return len(utf16.Encode([]rune(value)))
}

// restoreRegistryValue restores the exact presence and value observed before a mutation.
// restoreRegistryValue 恢复变更前观察到的精确存在状态与值。
func restoreRegistryValue(registry registryBackend, value registryValue) error {
	if value.Present {
		return registry.SetPath(value.Value, value.Type)
	}
	return registry.DeletePath()
}

// windowsRegistry accesses HKCU\Environment through the Windows registry API.
// windowsRegistry 通过 Windows 注册表 API 访问 HKCU\Environment。
type windowsRegistry struct{}

// ReadPath reads REG_SZ or REG_EXPAND_SZ PATH from the current user environment key.
// ReadPath 从当前用户环境键读取 REG_SZ 或 REG_EXPAND_SZ PATH。
func (windowsRegistry) ReadPath() (registryValue, error) {
	key, err := openEnvironmentKey(registryQueryValue | registrySetValue)
	if err != nil {
		return registryValue{}, err
	}
	defer syscall.RegCloseKey(key)

	name, err := syscall.UTF16PtrFromString("Path")
	if err != nil {
		return registryValue{}, err
	}
	var valueType uint32
	var size uint32
	err = syscall.RegQueryValueEx(key, name, nil, &valueType, nil, &size)
	if err != nil {
		if err == syscall.ERROR_FILE_NOT_FOUND {
			return registryValue{Type: registryValueExpandString, Present: false}, nil
		}
		return registryValue{}, err
	}
	if valueType != registryValueString && valueType != registryValueExpandString {
		return registryValue{}, fmt.Errorf("unsupported PATH registry type %d", valueType)
	}
	buffer := make([]byte, size)
	if size > 0 {
		if err := syscall.RegQueryValueEx(key, name, nil, &valueType, &buffer[0], &size); err != nil {
			return registryValue{}, err
		}
	}
	return registryValue{Value: decodeRegistryString(buffer[:size]), Type: valueType, Present: true}, nil
}

// SetPath writes one UTF-16 PATH registry value without touching machine-level variables.
// SetPath 写入一个 UTF-16 PATH 注册表值，不触碰系统级变量。
func (windowsRegistry) SetPath(value string, valueType uint32) error {
	if valueType != registryValueString && valueType != registryValueExpandString {
		return fmt.Errorf("unsupported PATH registry type %d", valueType)
	}
	key, err := openEnvironmentKey(registrySetValue)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	name, err := syscall.UTF16PtrFromString("Path")
	if err != nil {
		return err
	}
	encoded := encodeRegistryString(value)
	result, _, callErr := regSetValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(name)),
		0,
		uintptr(valueType),
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(len(encoded)),
	)
	if result != 0 {
		return syscall.Errno(result)
	}
	_ = callErr
	return nil
}

// DeletePath removes only the current user's PATH value.
// DeletePath 只删除当前用户的 PATH 值。
func (windowsRegistry) DeletePath() error {
	key, err := openEnvironmentKey(registrySetValue)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(key)
	name, err := syscall.UTF16PtrFromString("Path")
	if err != nil {
		return err
	}
	proc := syscall.NewLazyDLL("advapi32.dll").NewProc("RegDeleteValueW")
	result, _, callErr := proc.Call(uintptr(key), uintptr(unsafe.Pointer(name)))
	if result != 0 && result != uintptr(syscall.ERROR_FILE_NOT_FOUND) {
		return syscall.Errno(result)
	}
	if result == 0 || result == uintptr(syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return callErr
}

// openEnvironmentKey opens HKCU\Environment with the requested value access.
// openEnvironmentKey 以请求的值访问权限打开 HKCU\Environment。
func openEnvironmentKey(access uint32) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(currentUserHandle, name, 0, access, &key); err != nil {
		return 0, err
	}
	return key, nil
}

// decodeRegistryString decodes a NUL-terminated UTF-16 registry payload.
// decodeRegistryString 解码以 NUL 结尾的 UTF-16 注册表内容。
func decodeRegistryString(buffer []byte) string {
	if len(buffer)%2 != 0 {
		return ""
	}
	values := make([]uint16, len(buffer)/2)
	for index := range values {
		values[index] = binary.LittleEndian.Uint16(buffer[index*2:])
	}
	if end := indexOfUTF16NUL(values); end >= 0 {
		values = values[:end]
	}
	return string(utf16.Decode(values))
}

// encodeRegistryString encodes a PATH string as a UTF-16LE NUL-terminated payload.
// encodeRegistryString 将 PATH 字符串编码为 UTF-16LE NUL 结尾内容。
func encodeRegistryString(value string) []byte {
	values := utf16.Encode([]rune(value + "\x00"))
	buffer := make([]byte, len(values)*2)
	for index, value := range values {
		binary.LittleEndian.PutUint16(buffer[index*2:], value)
	}
	return buffer
}

// indexOfUTF16NUL finds the first registry string terminator.
// indexOfUTF16NUL 查找注册表字符串的第一个终止符。
func indexOfUTF16NUL(values []uint16) int {
	for index, value := range values {
		if value == 0 {
			return index
		}
	}
	return -1
}

// windowsEnvironmentBroadcaster broadcasts the standard environment update message.
// windowsEnvironmentBroadcaster 广播标准环境更新消息。
type windowsEnvironmentBroadcaster struct{}

// Broadcast sends WM_SETTINGCHANGE to all top-level windows with a bounded timeout.
// Broadcast 以有界超时向所有顶层窗口发送 WM_SETTINGCHANGE。
func (windowsEnvironmentBroadcaster) Broadcast() error {
	section, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return err
	}
	const (
		hwndBroadcast   = 0xffff
		wmSettingChange = 0x001a
		smtoBlock       = 0x0001
		smtoAbortIfHung = 0x0002
	)
	var result uintptr
	returnValue, _, callErr := sendMessageTimeoutW.Call(
		hwndBroadcast,
		wmSettingChange,
		0,
		uintptr(unsafe.Pointer(section)),
		smtoBlock|smtoAbortIfHung,
		5000,
		uintptr(unsafe.Pointer(&result)),
	)
	if returnValue == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("SendMessageTimeoutW did not deliver environment update")
	}
	return nil
}
