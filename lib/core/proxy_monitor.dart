import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data' show BytesBuilder;

import 'app_blocker.dart';
import 'event.dart';
import 'pii_detector.dart';
import 'process_resolver.dart';

/// Local forward proxy. Point an app/system proxy at 127.0.0.1:[port].
/// Plain HTTP is inspected for personal data; HTTPS (CONNECT) is relayed
/// untouched and logged as metadata only (no TLS decryption).
class ProxyMonitor {
  ProxyMonitor({this.port = 8899, this.logFile, required this.blocker}) : _resolver = ProcessResolver(port);

  final int port;
  final File? logFile;
  final AppBlocker blocker;
  final ProcessResolver _resolver;
  final _detector = PiiDetector();
  final _controller = StreamController<TransactionEvent>.broadcast();
  ServerSocket? _server;

  Stream<TransactionEvent> get events => _controller.stream;
  bool get running => _server != null;

  Future<void> start() async {
    _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, port);
    _server!.listen(_handle);
  }

  Future<void> stop() async {
    await _server?.close();
    _server = null;
  }

  void _emit(TransactionEvent e) {
    _controller.add(e);
    logFile?.writeAsStringSync('${jsonEncode(e.toJson())}\n', mode: FileMode.append);
  }

  Future<void> _handle(Socket client) async {
    // Resolve the owning process now, while the client connection is still open.
    final appF = _resolver.resolve(client.remotePort);
    try {
      final buf = BytesBuilder();
      final it = StreamIterator<List<int>>(client);
      var headerEnd = -1;
      while (headerEnd < 0 && await it.moveNext()) {
        buf.add(it.current);
        headerEnd = _find(buf.toBytes(), const [13, 10, 13, 10]);
        if (buf.length > 65536) break;
      }
      if (headerEnd < 0) return client.destroy();
      final bytes = buf.toBytes();
      final lines = latin1.decode(bytes.sublist(0, headerEnd)).split('\r\n');
      final parts = lines.first.split(' ');
      if (parts.length < 3) return client.destroy();

      if (!blocker.isEmpty) {
        final a = await appF;
        final host = parts[0] == 'CONNECT' ? parts[1].split(':').first : (Uri.tryParse(parts[1])?.host ?? parts[1]);
        final byApp = a != null && blocker.isBlocked(a.name, a.path);
        if (byApp || blocker.isHostBlocked(host)) {
          client.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
          await client.close();
          _emit(TransactionEvent(
            time: DateTime.now(),
            who: host,
            what: const [],
            how: byApp ? 'BLOCKED by PrivacyWatch (application)' : 'BLOCKED by PrivacyWatch (destination)',
            destination: parts[1],
            app: a?.toString(),
            appName: a?.name,
            appPath: a?.path,
          ));
          return;
        }
      }

      if (parts[0] == 'CONNECT') {
        await _tunnel(client, it, parts[1], appF);
      } else {
        await _forward(client, it, bytes, headerEnd, lines, parts[0], parts[1], appF);
      }
    } catch (_) {
      client.destroy();
    }
  }

  Future<void> _tunnel(Socket client, StreamIterator<List<int>> it, String target, Future<ClientApp?> appF) async {
    final started = DateTime.now();
    final hp = target.split(':');
    final host = hp[0];
    final port = hp.length > 1 ? int.tryParse(hp[1]) ?? 443 : 443;
    final upstream = await Socket.connect(host, port, timeout: const Duration(seconds: 10));
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    var up = 0, down = 0;
    var pending = 2; // client->server and server->client directions
    var emitted = false;

    // Emitted once when the tunnel closes, so byte counts are final.
    Future<void> finish() async {
      if (emitted) return;
      emitted = true;
      final a = await appF;
      _emit(TransactionEvent(
        time: started,
        who: host,
        what: const [],
        how: 'HTTPS tunnel (metadata only, encrypted)',
        destination: target,
        app: a?.toString(),
        appName: a?.name,
        appPath: a?.path,
        bytesUp: up,
        bytesDown: down,
        duration: DateTime.now().difference(started),
      ));
    }

    void doneOne() {
      if (--pending <= 0) finish();
    }

    void abort() {
      client.destroy();
      upstream.destroy();
      finish();
    }

    // close() flushes pending writes; destroy() would truncate the response.
    upstream.listen((d) {
      down += d.length;
      client.add(d);
    }, onDone: () {
      client.close();
      doneOne();
    }, onError: (_) => abort());
    unawaited(() async {
      try {
        while (await it.moveNext()) {
          up += it.current.length;
          upstream.add(it.current);
        }
        await upstream.close();
        doneOne();
      } catch (_) {
        abort();
      }
    }());
  }

  Future<void> _forward(Socket client, StreamIterator<List<int>> it, List<int> bytes, int headerEnd,
      List<String> lines, String method, String target, Future<ClientApp?> appF) async {
    final started = DateTime.now();
    final uri = Uri.parse(target);
    final headers = <String, String>{};
    for (final l in lines.skip(1)) {
      final i = l.indexOf(':');
      if (i > 0) headers[l.substring(0, i).trim().toLowerCase()] = l.substring(i + 1).trim();
    }
    final len = int.tryParse(headers['content-length'] ?? '') ?? 0;
    final body = BytesBuilder()..add(bytes.sublist(headerEnd + 4));
    while (body.length < len && await it.moveNext()) {
      body.add(it.current);
    }
    final bodyText = latin1.decode(body.toBytes());

    final matches = <PiiMatch>[
      ..._detector.scan(uri.toString(), 'url'),
      for (final e in headers.entries)
        if (e.key != 'host' && e.key != 'content-length') ..._detector.scan(e.value, 'header:${e.key}'),
      ..._detector.scan(bodyText, 'body'),
    ];

    // Relay bytes as-is so forwarded Content-Encoding/Content-Length stay valid.
    final c = HttpClient()..autoUncompress = false;
    var down = 0;
    try {
      final req = await c.openUrl(method, uri);
      req.followRedirects = false;
      headers.forEach((k, v) {
        if (!const {'proxy-connection', 'host', 'content-length', 'connection'}.contains(k)) {
          req.headers.set(k, v);
        }
      });
      if (!headers.containsKey('accept-encoding')) req.headers.removeAll('accept-encoding');
      req.add(body.toBytes());
      final res = await req.close();
      client.write('HTTP/1.1 ${res.statusCode} ${res.reasonPhrase}\r\nConnection: close\r\n');
      res.headers.forEach((n, v) {
        if (n != 'transfer-encoding' && n != 'connection') client.write('$n: ${v.join(', ')}\r\n');
      });
      client.write('\r\n');
      await client.addStream(res.map((d) {
        down += d.length;
        return d;
      }));
      await client.close();
    } finally {
      c.close();
      final a = await appF;
      _emit(TransactionEvent(
        time: started,
        who: [uri.host, if (headers['user-agent'] != null) headers['user-agent']!].join(' | '),
        what: matches,
        how: 'HTTP $method${bodyText.isNotEmpty ? ' with body' : ''}',
        destination: uri.toString(),
        app: a?.toString(),
        appName: a?.name,
        appPath: a?.path,
        bytesUp: headerEnd + 4 + body.length,
        bytesDown: down,
        duration: DateTime.now().difference(started),
      ));
    }
  }

  static int _find(List<int> data, List<int> pat) {
    for (var i = 0; i <= data.length - pat.length; i++) {
      var ok = true;
      for (var j = 0; j < pat.length; j++) {
        if (data[i + j] != pat[j]) {
          ok = false;
          break;
        }
      }
      if (ok) return i;
    }
    return -1;
  }
}
