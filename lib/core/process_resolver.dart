import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

class ClientApp {
  const ClientApp(this.name, this.pid, [this.path]);
  final String name;
  final int pid;
  final String? path;
  @override
  String toString() => '$name (PID $pid)';
}

typedef _GetTcpTableC = Uint32 Function(Pointer<Void>, Pointer<Uint32>, Int32, Uint32, Int32, Uint32);
typedef _GetTcpTableD = int Function(Pointer<Void>, Pointer<Uint32>, int, int, int, int);
typedef _OpenProcessC = Pointer<Void> Function(Uint32, Int32, Uint32);
typedef _OpenProcessD = Pointer<Void> Function(int, int, int);
typedef _QueryNameC = Int32 Function(Pointer<Void>, Uint32, Pointer<Utf16>, Pointer<Uint32>);
typedef _QueryNameD = int Function(Pointer<Void>, int, Pointer<Utf16>, Pointer<Uint32>);
typedef _CloseHandleC = Int32 Function(Pointer<Void>);
typedef _CloseHandleD = int Function(Pointer<Void>);

/// Resolves which local process owns a loopback client connection to the proxy.
/// Windows only (reads the TCP table in-process via iphlpapi, so even
/// short-lived programs are identified); returns null elsewhere or on failure.
class ProcessResolver {
  ProcessResolver(this.proxyPort);
  final int proxyPort;

  late final _getTcpTable =
      DynamicLibrary.open('iphlpapi.dll').lookupFunction<_GetTcpTableC, _GetTcpTableD>('GetExtendedTcpTable');
  late final _kernel32 = DynamicLibrary.open('kernel32.dll');
  late final _openProcess = _kernel32.lookupFunction<_OpenProcessC, _OpenProcessD>('OpenProcess');
  late final _queryName = _kernel32.lookupFunction<_QueryNameC, _QueryNameD>('QueryFullProcessImageNameW');
  late final _closeHandle = _kernel32.lookupFunction<_CloseHandleC, _CloseHandleD>('CloseHandle');

  Future<ClientApp?> resolve(int clientPort) async {
    if (!Platform.isWindows) return null;
    try {
      final pid = _pidFor(clientPort);
      if (pid == null) return null;
      final path = _pathFor(pid);
      if (path != null) return ClientApp(path.split(RegExp(r'[\\/]')).last, pid, path);
      return ClientApp(await _nameFor(pid), pid);
    } catch (_) {
      return null;
    }
  }

  static int _port(int v) => ((v & 0xff) << 8) | ((v >> 8) & 0xff);

  int? _pidFor(int clientPort) {
    const tcpTableOwnerPidAll = 5, afInet = 2;
    final size = calloc<Uint32>();
    Pointer<Uint8>? buf;
    try {
      _getTcpTable(nullptr, size, 0, afInet, tcpTableOwnerPidAll, 0);
      for (var attempt = 0; attempt < 3; attempt++) {
        buf = calloc<Uint8>(size.value + 4096);
        size.value += 4096;
        if (_getTcpTable(buf.cast(), size, 0, afInet, tcpTableOwnerPidAll, 0) == 0) {
          // Layout: DWORD count, then rows of 6 DWORDs (state, laddr, lport, raddr, rport, pid).
          final words = buf.cast<Uint32>().asTypedList(1 + 6 * buf.cast<Uint32>()[0]);
          for (var i = 0; i < words[0]; i++) {
            final b = 1 + i * 6;
            if (_port(words[b + 2]) == clientPort && _port(words[b + 4]) == proxyPort) return words[b + 5];
          }
          return null;
        }
        calloc.free(buf);
        buf = null;
      }
      return null;
    } finally {
      if (buf != null) calloc.free(buf);
      calloc.free(size);
    }
  }

  String? _pathFor(int pid) {
    const processQueryLimitedInformation = 0x1000;
    final h = _openProcess(processQueryLimitedInformation, 0, pid);
    if (h == nullptr) return null;
    final len = calloc<Uint32>()..value = 1024;
    final buf = calloc<Uint16>(1024).cast<Utf16>();
    try {
      return _queryName(h, 0, buf, len) != 0 ? buf.toDartString(length: len.value) : null;
    } finally {
      calloc.free(buf);
      calloc.free(len);
      _closeHandle(h);
    }
  }

  // Protected system processes cannot be opened; fall back to the process list for the name.
  Future<String> _nameFor(int pid) async {
    try {
      final out = (await Process.run('tasklist', ['/FI', 'PID eq $pid', '/FO', 'CSV', '/NH'])).stdout as String;
      final m = RegExp(r'^"([^"]+)"').firstMatch(out.trim());
      if (m != null) return m.group(1)!;
    } catch (_) {}
    return 'unknown';
  }
}
