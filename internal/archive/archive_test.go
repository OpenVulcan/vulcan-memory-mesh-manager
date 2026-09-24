// Package archive tests authenticated package extraction, receipt verification, and hostile archive rejection.
// archive 包测试认证安装包解压、清单校验和恶意压缩包拒绝行为。
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// zipFixtureEntry describes one synthetic ZIP member, including optional raw metadata for bomb tests.
// zipFixtureEntry 描述一个合成 ZIP 条目，包括压缩炸弹测试使用的原始元数据。
type zipFixtureEntry struct {
	// name is the archive path written to the ZIP central directory.
	// name 是写入 ZIP 中央目录的压缩包路径。
	name string

	// data is the literal member body for ordinary fixtures.
	// data 是普通测试条目的字面内容。
	data []byte

	// mode carries regular-file, directory, or symlink type bits into ZIP metadata.
	// mode 将普通文件、目录或符号链接类型位写入 ZIP 元数据。
	mode os.FileMode

	// rawHeader requests an entry with declared sizes that differ from its stored body.
	// rawHeader 请求创建声明尺寸与实际内容不同的条目。
	rawHeader *zip.FileHeader
}

// TestExtractZIPAcceptsVerifiedPackage checks ZIP extraction and exact package inventory validation.
// TestExtractZIPAcceptsVerifiedPackage 检查 ZIP 解包及包内文件清单精确校验。
func TestExtractZIPAcceptsVerifiedPackage(t *testing.T) {
	expected := testExpected("windows-x64")
	files := testPayloadFiles()
	entries := zipPayloadEntries(t, expected, files)
	archiveBytes := makeZIP(t, entries)
	archivePath, stagePath := writeFixture(t, archiveBytes)
	expected = withArchiveDigest(expected, archiveBytes)

	result, err := Extract(context.Background(), archivePath, stagePath, expected)
	if err != nil {
		t.Fatalf("Extract returned an error: %v", err)
	}
	if result.Root != filepath.Join(stagePath, packageDirectoryName(expected)) {
		t.Fatalf("package root is %q", result.Root)
	}
	if runtime.GOOS != "windows" {
		rootInfo, err := os.Stat(result.Root)
		if err != nil {
			t.Fatalf("stat package root: %v", err)
		}
		if rootInfo.Mode().Perm()&0o755 != 0o755 {
			t.Fatalf("package root is not traversable by the service account: %v", rootInfo.Mode().Perm())
		}
	}
	if result.Receipt.Capabilities.SchemaVersion != 1 || len(result.Receipt.Capabilities.StorageModes) != 4 {
		t.Fatalf("unexpected validated capabilities: %#v", result.Receipt.Capabilities)
	}
	for name, want := range files {
		actual, err := os.ReadFile(filepath.Join(result.Root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read extracted file %q: %v", name, err)
		}
		if !bytes.Equal(actual, want) {
			t.Fatalf("extracted file %q changed", name)
		}
	}
	entriesAfterInstall, err := os.ReadDir(stagePath)
	if err != nil {
		t.Fatalf("read staging root: %v", err)
	}
	if len(entriesAfterInstall) != 1 || entriesAfterInstall[0].Name() != packageDirectoryName(expected) {
		t.Fatalf("staging root contains unexpected entries: %#v", entriesAfterInstall)
	}
}

// TestExtractTarGzipAcceptsPackageAndPreservesExecutableBits checks tar.gz support and Unix executable permissions.
// TestExtractTarGzipAcceptsPackageAndPreservesExecutableBits 检查 tar.gz 支持和 Unix 可执行权限保留。
func TestExtractTarGzipAcceptsPackageAndPreservesExecutableBits(t *testing.T) {
	expected := testExpected("linux-x64")
	files := testPayloadFiles()
	archiveBytes := makeTarGzip(t, expected, files, nil)
	archivePath, stagePath := writeFixture(t, archiveBytes)
	expected = withArchiveDigest(expected, archiveBytes)

	result, err := Extract(context.Background(), archivePath, stagePath, expected)
	if err != nil {
		t.Fatalf("Extract returned an error: %v", err)
	}
	if result.Receipt.Version != expected.Version || result.Receipt.Platform != expected.Platform {
		t.Fatalf("unexpected receipt identity: %#v", result.Receipt)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(result.Root, "bin", "vmm-local"))
		if err != nil {
			t.Fatalf("stat extracted executable: %v", err)
		}
		if info.Mode().Perm()&0o111 != 0o111 {
			t.Fatalf("executable permission was not preserved: %v", info.Mode().Perm())
		}
	}
}

// TestExtractRejectsUnsafeZIPPaths checks absolute, traversal, Windows, ADS, and backslash path forms.
// TestExtractRejectsUnsafeZIPPaths 检查绝对路径、目录穿越、Windows 路径、ADS 和反斜杠路径。
func TestExtractRejectsUnsafeZIPPaths(t *testing.T) {
	unsafeNames := []string{
		"../escape",
		"vulcan-memory-mesh-v1.2.3-windows-x64/../escape",
		"other-release/file",
		"/absolute",
		"C:/drive/file",
		"vulcan-memory-mesh-v1.2.3-windows-x64/configs/file:stream",
		"vulcan-memory-mesh-v1.2.3-windows-x64/configs/file.",
		"vulcan-memory-mesh-v1.2.3-windows-x64/configs/NUL.txt",
		`vulcan-memory-mesh-v1.2.3-windows-x64\bin\file`,
	}
	for _, name := range unsafeNames {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			expected := testExpected("windows-x64")
			files := testPayloadFiles()
			entries := zipPayloadEntries(t, expected, files)
			entries = append(entries, zipFixtureEntry{name: name, data: []byte("bad"), mode: 0o644})
			assertExtractionRejected(t, expected, makeZIP(t, entries))
		})
	}
}

// TestExtractRejectsZIPLinksAndSpecialTypes checks symlink and special-file metadata rejection.
// TestExtractRejectsZIPLinksAndSpecialTypes 检查符号链接及特殊文件元数据拒绝。
func TestExtractRejectsZIPLinksAndSpecialTypes(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"symlink": os.ModeSymlink | 0o777,
		"fifo":    os.ModeNamedPipe | 0o600,
	} {
		t.Run(name, func(t *testing.T) {
			expected := testExpected("windows-x64")
			files := testPayloadFiles()
			entries := zipPayloadEntries(t, expected, files)
			entries = append(entries, zipFixtureEntry{
				name: packageDirectoryName(expected) + "/evil",
				data: []byte("target"),
				mode: mode,
			})
			assertExtractionRejected(t, expected, makeZIP(t, entries))
		})
	}
}

// TestExtractRejectsDuplicateAndCaseCollidingZIPEntries checks exact duplicates and Windows case collisions.
// TestExtractRejectsDuplicateAndCaseCollidingZIPEntries 检查完全重复条目和 Windows 大小写碰撞。
func TestExtractRejectsDuplicateAndCaseCollidingZIPEntries(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		expected := testExpected("windows-x64")
		files := testPayloadFiles()
		entries := zipPayloadEntries(t, expected, files)
		duplicate := packageDirectoryName(expected) + "/bin/vmm-local"
		entries = append(entries, zipFixtureEntry{name: duplicate, data: []byte("second"), mode: 0o755})
		assertExtractionRejected(t, expected, makeZIP(t, entries))
	})
	t.Run("case-collision", func(t *testing.T) {
		expected := testExpected("windows-x64")
		files := testPayloadFiles()
		entries := zipPayloadEntries(t, expected, files)
		entries = append(entries, zipFixtureEntry{
			name: packageDirectoryName(expected) + "/Bin/other",
			data: []byte("second"),
			mode: 0o644,
		})
		assertExtractionRejected(t, expected, makeZIP(t, entries))
	})
}

// TestExtractRejectsReceiptIdentityCapabilityAndInventoryMismatch covers package metadata and payload integrity failures.
// TestExtractRejectsReceiptIdentityCapabilityAndInventoryMismatch 覆盖包身份、能力和负载完整性错误。
func TestExtractRejectsReceiptIdentityCapabilityAndInventoryMismatch(t *testing.T) {
	tests := []struct {
		name       string
		mutateJSON func([]byte) []byte
		files      map[string][]byte
	}{
		{
			name: "wrong-version",
			mutateJSON: func(data []byte) []byte {
				return bytes.Replace(data, []byte(`"version":"v1.2.3"`), []byte(`"version":"v9.9.9"`), 1)
			},
			files: testPayloadFiles(),
		},
		{
			name: "unknown-mode",
			mutateJSON: func(data []byte) []byte {
				return bytes.Replace(data, []byte(`"storage_modes":["split","controller","native","combined"]`), []byte(`"storage_modes":["split","controller","unknown","combined"]`), 1)
			},
			files: testPayloadFiles(),
		},
		{
			name: "unknown-capability-schema",
			mutateJSON: func(data []byte) []byte {
				return bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
			},
			files: testPayloadFiles(),
		},
		{
			name: "unknown-combined-provider",
			mutateJSON: func(data []byte) []byte {
				return bytes.Replace(data, []byte(`"provider":"postgres"`), []byte(`"provider":"mysql"`), 1)
			},
			files: testPayloadFiles(),
		},
		{
			name: "unknown-receipt-field",
			mutateJSON: func(data []byte) []byte {
				return bytes.Replace(data, []byte("{"), []byte(`{"unexpected":true,`), 1)
			},
			files: testPayloadFiles(),
		},
		{
			name:       "payload-digest-mismatch",
			mutateJSON: func(data []byte) []byte { return data },
			files:      map[string][]byte{"bin/vmm-local": []byte("changed"), "configs/base.yaml": []byte("mode: native\n")},
		},
		{
			name:       "unlisted-payload-file",
			mutateJSON: func(data []byte) []byte { return data },
			files:      testPayloadFiles(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := testExpected("windows-x64")
			manifestFiles := test.files
			if test.name == "payload-digest-mismatch" {
				manifestFiles = testPayloadFiles()
			}
			receipt := testReceipt(expected, manifestFiles)
			receiptBytes, err := json.Marshal(receipt)
			if err != nil {
				t.Fatalf("marshal receipt: %v", err)
			}
			receiptBytes = test.mutateJSON(receiptBytes)
			entries := make([]zipFixtureEntry, 0, len(test.files)+2)
			for name, body := range test.files {
				entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/" + name, data: body, mode: 0o644})
			}
			if test.name == "unlisted-payload-file" {
				entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/extra.txt", data: []byte("extra"), mode: 0o644})
			}
			entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/release-manifest.json", data: receiptBytes, mode: 0o644})
			assertExtractionRejected(t, expected, makeZIP(t, entries))
		})
	}
}

// TestValidateCapabilitiesAllowsAValidatedSubset leaves required full-mode policy to installation orchestration.
// TestValidateCapabilitiesAllowsAValidatedSubset 将完整模式策略留给安装编排层。
func TestValidateCapabilitiesAllowsAValidatedSubset(t *testing.T) {
	capabilities := Capabilities{SchemaVersion: 1, StorageModes: []StorageMode{StorageModeNative}}
	if err := validateCapabilities(capabilities); err != nil {
		t.Fatalf("valid capability subset was rejected: %v", err)
	}
}

// TestExtractRejectsDuplicateReceiptKeys ensures JSON's last-key-wins behavior cannot hide a receipt mutation.
// TestExtractRejectsDuplicateReceiptKeys 确保 JSON 的重复键覆盖行为无法隐藏清单字段。
func TestExtractRejectsDuplicateReceiptKeys(t *testing.T) {
	expected := testExpected("windows-x64")
	files := testPayloadFiles()
	receipt := testReceipt(expected, files)
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	receiptBytes = bytes.Replace(receiptBytes, []byte(`"manifest_schema":2`), []byte(`"manifest_schema":2,"manifest_schema":2`), 1)
	entries := make([]zipFixtureEntry, 0, len(files)+1)
	for name, body := range files {
		entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/" + name, data: body, mode: 0o644})
	}
	entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/release-manifest.json", data: receiptBytes, mode: 0o644})
	assertExtractionRejected(t, expected, makeZIP(t, entries))
}

// TestExtractRejectsArchiveDigestAndNonEmptyStage ensures authentication failure leaves existing paths untouched.
// TestExtractRejectsArchiveDigestAndNonEmptyStage 确保认证失败时保留已有路径且不写入暂存目录。
func TestExtractRejectsArchiveDigestAndNonEmptyStage(t *testing.T) {
	t.Run("digest-mismatch", func(t *testing.T) {
		expected := testExpected("windows-x64")
		archiveBytes := makeZIP(t, zipPayloadEntries(t, expected, testPayloadFiles()))
		archivePath, stagePath := writeFixture(t, archiveBytes)
		installPath := filepath.Join(filepath.Dir(stagePath), "old-install", "keep.txt")
		if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
			t.Fatalf("create old install: %v", err)
		}
		if err := os.WriteFile(installPath, []byte("keep"), 0o600); err != nil {
			t.Fatalf("write old install: %v", err)
		}
		expected = withArchiveDigest(expected, archiveBytes)
		expected.ArchiveSHA256 = strings.Repeat("0", 64)
		if _, err := Extract(context.Background(), archivePath, stagePath, expected); err == nil {
			t.Fatal("Extract accepted an archive with the wrong signed digest")
		}
		assertDirectoryEmpty(t, stagePath)
		actual, err := os.ReadFile(installPath)
		if err != nil || string(actual) != "keep" {
			t.Fatalf("old installation changed: data=%q err=%v", actual, err)
		}
	})
	t.Run("non-empty-stage", func(t *testing.T) {
		expected := testExpected("windows-x64")
		archiveBytes := makeZIP(t, zipPayloadEntries(t, expected, testPayloadFiles()))
		archivePath, stagePath := writeFixture(t, archiveBytes)
		marker := filepath.Join(stagePath, "marker")
		if err := os.WriteFile(marker, []byte("existing"), 0o600); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		expected = withArchiveDigest(expected, archiveBytes)
		if _, err := Extract(context.Background(), archivePath, stagePath, expected); err == nil {
			t.Fatal("Extract accepted a non-empty staging root")
		}
		actual, err := os.ReadFile(marker)
		if err != nil || string(actual) != "existing" {
			t.Fatalf("existing staging file changed: data=%q err=%v", actual, err)
		}
	})
}

// TestExtractRejectsZIPBombMetadata rejects oversized uncompressed metadata before opening member streams.
// TestExtractRejectsZIPBombMetadata 在打开条目数据流前拒绝过大的 ZIP 解压尺寸元数据。
func TestExtractRejectsZIPBombMetadata(t *testing.T) {
	expected := testExpected("windows-x64")
	declared := &zip.FileHeader{
		Name:               packageDirectoryName(expected) + "/huge.bin",
		Method:             zip.Store,
		CompressedSize64:   0,
		UncompressedSize64: uint64(maxExpandedBytes) + 1,
		CRC32:              crc32.ChecksumIEEE(nil),
	}
	declared.SetMode(0o644)
	archiveBytes := makeZIP(t, []zipFixtureEntry{{rawHeader: declared}})
	assertExtractionRejected(t, expected, archiveBytes)
}

// TestExtractRejectsTarLinksSpecialFilesAndUnsafePaths checks tar-specific hostile entry types and names.
// TestExtractRejectsTarLinksSpecialFilesAndUnsafePaths 检查 tar 专属恶意条目类型和路径。
func TestExtractRejectsTarLinksSpecialFilesAndUnsafePaths(t *testing.T) {
	cases := []struct {
		name   string
		header tar.Header
	}{
		{name: "symlink", header: tar.Header{Name: "vulcan-memory-mesh-v1.2.3-linux-x64/link", Typeflag: tar.TypeSymlink, Linkname: "../../outside", Mode: 0o777}},
		{name: "hardlink", header: tar.Header{Name: "vulcan-memory-mesh-v1.2.3-linux-x64/link", Typeflag: tar.TypeLink, Linkname: "bin/vmm-local", Mode: 0o644}},
		{name: "device", header: tar.Header{Name: "vulcan-memory-mesh-v1.2.3-linux-x64/device", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 2, Mode: 0o600}},
		{name: "traversal", header: tar.Header{Name: "vulcan-memory-mesh-v1.2.3-linux-x64/../escape", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}},
		{name: "backslash", header: tar.Header{Name: `vulcan-memory-mesh-v1.2.3-linux-x64\escape`, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			expected := testExpected("linux-x64")
			archiveBytes := makeTarGzip(t, expected, testPayloadFiles(), &test.header)
			assertExtractionRejected(t, expected, archiveBytes)
		})
	}
}

// TestExtractRejectsTarCaseCollision checks paths that would alias on a case-insensitive filesystem.
// TestExtractRejectsTarCaseCollision 检查在大小写不敏感文件系统上会相互别名的路径。
func TestExtractRejectsTarCaseCollision(t *testing.T) {
	expected := testExpected("linux-x64")
	extra := &tar.Header{Name: packageDirectoryName(expected) + "/Bin/other", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len("extra"))}
	archiveBytes := makeTarGzip(t, expected, testPayloadFiles(), extra)
	assertExtractionRejected(t, expected, archiveBytes)
}

// TestExtractRejectsCorruptTarGzipTrailer verifies the gzip checksum even when the external artifact digest matches.
// TestExtractRejectsCorruptTarGzipTrailer 验证即使外层资产摘要匹配也会检查 gzip 校验和。
func TestExtractRejectsCorruptTarGzipTrailer(t *testing.T) {
	expected := testExpected("linux-x64")
	archiveBytes := makeTarGzip(t, expected, testPayloadFiles(), nil)
	archiveBytes[len(archiveBytes)-1] ^= 0xff
	assertExtractionRejected(t, expected, archiveBytes)
}

// TestEntryTrackerEnforcesEntryAndExpandedByteLimits checks both independent resource bounds directly.
// TestEntryTrackerEnforcesEntryAndExpandedByteLimits 直接检查条目数量和解压字节数两个独立资源上限。
func TestEntryTrackerEnforcesEntryAndExpandedByteLimits(t *testing.T) {
	tracker := newEntryTracker("vulcan-memory-mesh-v1.2.3-linux-x64")
	if err := tracker.addPath("payload", false, uint64(maxExpandedBytes)+1); err == nil {
		t.Fatal("entry tracker accepted an oversized expansion")
	}
	tracker = newEntryTracker("vulcan-memory-mesh-v1.2.3-linux-x64")
	for index := 0; index < maxArchiveEntries; index++ {
		name := "entry-" + strconv.Itoa(index) + ".bin"
		if err := tracker.addPath(name, false, 0); err != nil {
			t.Fatalf("entry %d unexpectedly failed: %v", index, err)
		}
	}
	if err := tracker.addPath("last.bin", false, 0); err == nil {
		t.Fatal("entry tracker accepted too many entries")
	}
}

// testExpected creates the fixed test identity for one supported VMM platform.
// testExpected 为一个受支持的 VMM 平台创建固定测试身份。
func testExpected(platform string) ExpectedRelease {
	return ExpectedRelease{
		Version:  "v1.2.3",
		Commit:   strings.Repeat("a", 40),
		Platform: platform,
		Target:   platformTargets[platform],
	}
}

// testPayloadFiles returns a small runtime payload that exercises nested and executable paths.
// testPayloadFiles 返回包含嵌套路径和可执行文件的小型运行时负载。
func testPayloadFiles() map[string][]byte {
	return map[string][]byte{
		"bin/vmm-local":     []byte("vmm executable fixture"),
		"configs/base.yaml": []byte("storage:\n  mode: native\n"),
	}
}

// testReceipt builds a release receipt whose payload map excludes the receipt itself.
// testReceipt 创建一个不将自身列入负载映射的发行清单。
func testReceipt(expected ExpectedRelease, files map[string][]byte) Receipt {
	digests := make(map[string]string, len(files))
	for name, body := range files {
		sum := sha256.Sum256(body)
		digests[name] = hex.EncodeToString(sum[:])
	}
	return Receipt{
		ManifestSchema: ManifestSchemaVersion,
		Version:        expected.Version,
		Commit:         expected.Commit,
		Platform:       expected.Platform,
		Target:         expected.Target,
		StorageMode:    StorageModeNative,
		StorageProfile: "all",
		Capabilities: Capabilities{
			SchemaVersion: 1,
			StorageModes:  []StorageMode{StorageModeSplit, StorageModeController, StorageModeNative, StorageModeCombined},
			Combined:      &CombinedCapability{Provider: "postgres", Flavors: []string{"standard", "paradedb"}},
		},
		Files: digests,
	}
}

// zipPayloadEntries encodes ordinary payload files and a valid package receipt as ZIP entries.
// zipPayloadEntries 将普通负载文件和有效包内清单编码为 ZIP 条目。
func zipPayloadEntries(t *testing.T, expected ExpectedRelease, files map[string][]byte) []zipFixtureEntry {
	t.Helper()
	entries := make([]zipFixtureEntry, 0, len(files)+1)
	for name, body := range files {
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		entries = append(entries, zipFixtureEntry{name: packageDirectoryName(expected) + "/" + name, data: body, mode: mode})
	}
	receiptBytes, err := json.Marshal(testReceipt(expected, files))
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	entries = append(entries, zipFixtureEntry{
		name: packageDirectoryName(expected) + "/release-manifest.json",
		data: receiptBytes,
		mode: 0o644,
	})
	return entries
}

// makeZIP serializes ordinary and raw metadata members into a ZIP byte slice.
// makeZIP 将普通条目和原始元数据条目序列化为 ZIP 字节切片。
func makeZIP(t *testing.T, entries []zipFixtureEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		if entry.rawHeader != nil {
			stream, err := writer.CreateRaw(entry.rawHeader)
			if err != nil {
				t.Fatalf("create raw ZIP member: %v", err)
			}
			if len(entry.data) != 0 {
				if _, err := stream.Write(entry.data); err != nil {
					t.Fatalf("write raw ZIP member: %v", err)
				}
			}
			continue
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode == 0 {
			entry.mode = 0o644
		}
		header.SetMode(entry.mode)
		stream, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create ZIP member %q: %v", entry.name, err)
		}
		if _, err := stream.Write(entry.data); err != nil {
			t.Fatalf("write ZIP member %q: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP fixture: %v", err)
	}
	return buffer.Bytes()
}

// makeTarGzip writes a tar.gz fixture and can append one hostile tar header after ordinary payload entries.
// makeTarGzip 写入 tar.gz 测试压缩包，并可在正常负载后追加一个恶意 tar 文件头。
func makeTarGzip(t *testing.T, expected ExpectedRelease, files map[string][]byte, extra *tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	rootName := packageDirectoryName(expected)
	writeTarHeader(t, tarWriter, &tar.Header{Name: rootName, Typeflag: tar.TypeDir, Mode: 0o755})
	writeTarHeader(t, tarWriter, &tar.Header{Name: rootName + "/bin", Typeflag: tar.TypeDir, Mode: 0o755})
	writeTarHeader(t, tarWriter, &tar.Header{Name: rootName + "/configs", Typeflag: tar.TypeDir, Mode: 0o755})
	for name, body := range files {
		mode := int64(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		header := &tar.Header{Name: rootName + "/" + name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body))}
		writeTarHeader(t, tarWriter, header)
		if _, err := tarWriter.Write(body); err != nil {
			t.Fatalf("write tar member %q: %v", name, err)
		}
	}
	receiptBytes, err := json.Marshal(testReceipt(expected, files))
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	receiptHeader := &tar.Header{Name: rootName + "/release-manifest.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(receiptBytes))}
	writeTarHeader(t, tarWriter, receiptHeader)
	if _, err := tarWriter.Write(receiptBytes); err != nil {
		t.Fatalf("write tar receipt: %v", err)
	}
	if extra != nil {
		if extra.Size > 0 && extra.Typeflag == tar.TypeReg {
			extraBody := []byte("extra")
			if int64(len(extraBody)) < extra.Size {
				extraBody = append(extraBody, bytes.Repeat([]byte("x"), int(extra.Size)-len(extraBody))...)
			}
			if int64(len(extraBody)) > extra.Size {
				extraBody = extraBody[:extra.Size]
			}
			writeTarHeader(t, tarWriter, extra)
			if _, err := tarWriter.Write(extraBody); err != nil {
				t.Fatalf("write extra tar member: %v", err)
			}
		} else {
			writeTarHeader(t, tarWriter, extra)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar fixture: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip fixture: %v", err)
	}
	return buffer.Bytes()
}

// writeTarHeader writes one tar header and reports fixture construction errors immediately.
// writeTarHeader 写入一个 tar 文件头，并立即报告测试数据构造错误。
func writeTarHeader(t *testing.T, writer *tar.Writer, header *tar.Header) {
	t.Helper()
	if err := writer.WriteHeader(header); err != nil {
		t.Fatalf("write tar header %q: %v", header.Name, err)
	}
}

// writeFixture writes archive bytes and creates a fresh empty staging directory for one extraction attempt.
// writeFixture 写入压缩包字节，并为一次解包尝试创建全新的空暂存目录。
func writeFixture(t *testing.T, archiveBytes []byte) (string, string) {
	t.Helper()
	base := t.TempDir()
	archivePath := filepath.Join(base, "release.zip")
	if err := os.WriteFile(archivePath, archiveBytes, 0o600); err != nil {
		t.Fatalf("write archive fixture: %v", err)
	}
	stagePath := filepath.Join(base, "staging")
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		t.Fatalf("create staging fixture: %v", err)
	}
	return archivePath, stagePath
}

// withArchiveDigest binds a fixture's actual bytes to the expected signed artifact metadata.
// withArchiveDigest 将测试压缩包的实际字节绑定到预期签名资产元数据。
func withArchiveDigest(expected ExpectedRelease, data []byte) ExpectedRelease {
	sum := sha256.Sum256(data)
	expected.ArchiveBytes = int64(len(data))
	expected.ArchiveSHA256 = hex.EncodeToString(sum[:])
	return expected
}

// assertExtractionRejected verifies a signed-byte fixture fails and leaves staging empty.
// assertExtractionRejected 验证签名字节对应的测试压缩包会失败且暂存目录保持为空。
func assertExtractionRejected(t *testing.T, expected ExpectedRelease, archiveBytes []byte) {
	t.Helper()
	archivePath, stagePath := writeFixture(t, archiveBytes)
	expected = withArchiveDigest(expected, archiveBytes)
	if _, err := Extract(context.Background(), archivePath, stagePath, expected); err == nil {
		t.Fatal("Extract accepted a hostile or invalid archive")
	}
	assertDirectoryEmpty(t, stagePath)
}

// assertDirectoryEmpty checks that failed extraction did not leave partial package files behind.
// assertDirectoryEmpty 检查解包失败后没有留下部分安装包文件。
func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read staging directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed extraction left staging entries: %#v", entries)
	}
}
