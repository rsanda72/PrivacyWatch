import 'dart:io';

import 'package:flutter/material.dart';

import 'core/app_blocker.dart';
import 'core/event.dart';
import 'core/pii_detector.dart';
import 'core/proxy_monitor.dart';
import 'critical_dialog.dart';
import 'report_page.dart';

void main() => runApp(const PrivacyWatchApp());

class PrivacyWatchApp extends StatelessWidget {
  const PrivacyWatchApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'PrivacyWatch',
        theme: ThemeData(colorSchemeSeed: Colors.teal, useMaterial3: true),
        home: const HomePage(),
      );
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final _events = <TransactionEvent>[];
  final _count = ValueNotifier<int>(0);
  final _blocker = AppBlocker();
  final _alerts = <TransactionEvent>[];
  final _alerted = <String>{};
  bool _alertOpen = false;
  ProxyMonitor? _monitor;
  bool _flash = false;
  String? _error;

  // Proxy capture works on desktop; mobile needs a local VPN service (see README).
  bool get _supported => Platform.isWindows || Platform.isMacOS || Platform.isLinux;

  Future<void> _toggle() async {
    if (_monitor?.running ?? false) {
      await _monitor!.stop();
      setState(() {});
      return;
    }
    try {
      final home = Platform.environment['USERPROFILE'] ?? Platform.environment['HOME'] ?? '.';
      final dir = Directory('$home/PrivacyWatch')..createSync(recursive: true);
      final m = ProxyMonitor(logFile: File('${dir.path}/transactions.jsonl'), blocker: _blocker);
      await m.start();
      m.events.listen(_onEvent);
      setState(() {
        _monitor = m;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = '$e');
    }
  }

  void _onEvent(TransactionEvent e) {
    if (!mounted) return;
    _count.value++;
    setState(() {
      _events.insert(0, e);
      _flash = e.what.isNotEmpty;
    });
    if (e.what.isNotEmpty) {
      Future.delayed(const Duration(milliseconds: 700), () {
        if (mounted) setState(() => _flash = false);
      });
    }
    if (e.severity == Severity.critical) _queueAlert(e);
  }

  // One alert at a time; the same app + data types only alerts once per session.
  void _queueAlert(TransactionEvent e) {
    if (_blocker.isBlocked(e.appName, e.appPath)) return;
    final key = '${e.appName}|${(e.what.map((m) => m.category.name).toSet().toList()..sort()).join(',')}';
    if (!_alerted.add(key)) return;
    _alerts.add(e);
    _showNextAlert();
  }

  Future<void> _showNextAlert() async {
    if (_alertOpen || _alerts.isEmpty || !mounted) return;
    _alertOpen = true;
    final e = _alerts.removeAt(0);
    await showDialog<void>(
      context: context,
      builder: (_) => CriticalAlertDialog(event: e, blocker: _blocker, onViewReport: _openReport),
    );
    _alertOpen = false;
    _showNextAlert();
  }

  void _openReport() => Navigator.of(context)
      .push(MaterialPageRoute(builder: (_) => ReportPage(liveEvents: _events, liveCount: _count)));

  @override
  Widget build(BuildContext context) {
    final running = _monitor?.running ?? false;
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      color: _flash ? Colors.red.shade200 : Colors.transparent,
      child: Scaffold(
        backgroundColor: Colors.transparent,
        appBar: AppBar(title: const Text('PrivacyWatch'), actions: [
          IconButton(
            tooltip: 'Blocked applications',
            icon: const Icon(Icons.block),
            onPressed: () => showDialog<void>(context: context, builder: (_) => BlockedAppsDialog(blocker: _blocker)),
          ),
          IconButton(
            tooltip: 'Clear',
            icon: const Icon(Icons.delete_sweep),
            onPressed: () => setState(_events.clear),
          ),
        ]),
        floatingActionButton: Row(mainAxisSize: MainAxisSize.min, children: [
          FloatingActionButton.extended(
            heroTag: 'report',
            onPressed: _openReport,
            icon: const Icon(Icons.analytics),
            label: const Text('Report / Analysis'),
          ),
          if (_supported) ...[
            const SizedBox(width: 12),
            FloatingActionButton.extended(
              heroTag: 'toggle',
              onPressed: _toggle,
              icon: Icon(running ? Icons.stop : Icons.play_arrow),
              label: Text(running ? 'Stop' : 'Start monitoring'),
            ),
          ],
        ]),
        body: Column(children: [
          if (!_supported)
            const ListTile(
              leading: Icon(Icons.info),
              title: Text('Mobile capture (local VPN service) is not implemented yet.'),
            ),
          if (running)
            const ListTile(
              leading: Icon(Icons.shield),
              title: Text('Listening on 127.0.0.1:8899 - set this as your HTTP proxy.'),
              subtitle: Text('HTTPS is logged as metadata only; contents are not decrypted.'),
            ),
          if (_error != null) ListTile(leading: const Icon(Icons.error), title: Text(_error!)),
          Expanded(
            child: ListView.builder(
              itemCount: _events.length,
              itemBuilder: (_, i) {
                final e = _events[i];
                final hit = e.what.isNotEmpty;
                return ListTile(
                  leading: Icon(hit ? Icons.warning_amber : Icons.lock_outline,
                      color: severityColor(e.severity)),
                  trailing: hit ? SeverityChip(e.severity) : null,
                  title: Text('${e.app ?? 'unknown app'}  ->  ${e.host}'),
                  subtitle: Text([
                    '${e.how}  |  up ${TransactionEvent.formatBytes(e.bytesUp)}  down ${TransactionEvent.formatBytes(e.bytesDown)}  |  ${e.duration.inMilliseconds} ms',
                    e.time.toIso8601String(),
                    if (e.tracker != null) 'Behavioral tracker: ${e.tracker!.owner} (${e.tracker!.category})',
                    if (hit) e.what.map((m) => '${m.category.label} (${m.where}: ${m.redacted})').join('; '),
                  ].join('\n')),
                  isThreeLine: true,
                );
              },
            ),
          ),
        ]),
      ),
    );
  }
}
