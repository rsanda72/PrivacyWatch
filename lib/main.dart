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
        debugShowCheckedModeBanner: false,
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
  late final AppBlocker _blocker = AppBlocker(storeFile: File('${_dataDir.path}/blocks.json'));
  final _inbox = <TransactionEvent>[]; // every Critical finding this session, newest first
  final _unseen = <TransactionEvent>[];
  final _alerted = <String>{};
  bool _alertOpen = false;
  ProxyMonitor? _monitor;
  bool _flash = false;
  String? _error;

  static Directory get _dataDir {
    final home = Platform.environment['USERPROFILE'] ?? Platform.environment['HOME'] ?? '.';
    return Directory('$home/PrivacyWatch')..createSync(recursive: true);
  }

  @override
  void initState() {
    super.initState();
    _blocker.load().then((_) {
      if (mounted) setState(() {});
    });
  }

  // Proxy capture works on desktop; mobile needs a local VPN service (see README).
  bool get _supported => Platform.isWindows || Platform.isMacOS || Platform.isLinux;

  Future<void> _toggle() async {
    if (_monitor?.running ?? false) {
      await _monitor!.stop();
      setState(() {});
      return;
    }
    try {
      final m = ProxyMonitor(logFile: File('${_dataDir.path}/transactions.jsonl'), blocker: _blocker);
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

  // Every Critical finding is kept in the inbox (alert icon). A new one pops up only when no pop-up is open;
  // closing a pop-up never chains into the next, so one click always gets you out.
  void _queueAlert(TransactionEvent e) {
    if (_blocker.isBlocked(e.appName, e.appPath)) return;
    final key = '${e.appName}|${(e.what.map((m) => m.category.name).toSet().toList()..sort()).join(',')}';
    if (!_alerted.add(key)) return;
    setState(() {
      _inbox.insert(0, e);
      _unseen.add(e);
    });
    if (!_alertOpen) _openAlert(e);
  }

  Future<void> _openAlert(TransactionEvent e) async {
    if (!mounted) return;
    _alertOpen = true;
    setState(() => _unseen.remove(e));
    await showDialog<void>(
      context: context,
      builder: (_) => CriticalAlertDialog(
        event: e,
        blocker: _blocker,
        onViewReport: _openReport,
        history: List.of(_events),
        waiting: _unseen.length,
      ),
    );
    _alertOpen = false;
  }

  Future<void> _openInbox() async {
    final picked = await showDialog<TransactionEvent>(
      context: context,
      builder: (ctx) => AlertInboxDialog(alerts: List.of(_inbox), unseen: Set.of(_unseen)),
    );
    if (picked != null) await _openAlert(picked);
  }

  void _openReport() => Navigator.of(context)
      .push(MaterialPageRoute(builder: (_) => ReportPage(liveEvents: _events, liveCount: _count, blocker: _blocker, dataDir: _dataDir)));

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
            tooltip: 'Critical alerts (${_inbox.length}, ${_unseen.length} not yet viewed)',
            icon: Badge(
              isLabelVisible: _inbox.isNotEmpty,
              label: Text('${_unseen.isEmpty ? _inbox.length : _unseen.length}'),
              backgroundColor: _unseen.isEmpty ? Colors.grey : Colors.red.shade800,
              child: const Icon(Icons.gpp_maybe),
            ),
            onPressed: _openInbox,
          ),
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
          PopupMenuButton<String>(
            tooltip: 'Options',
            onSelected: (v) {
              switch (v) {
                case 'report':
                  _openReport();
                case 'alerts':
                  _openInbox();
                case 'blocked':
                  showDialog<void>(context: context, builder: (_) => BlockedAppsDialog(blocker: _blocker));
                case 'toggle':
                  _toggle();
                case 'clear':
                  setState(_events.clear);
              }
            },
            itemBuilder: (_) => [
              const PopupMenuItem(value: 'report', child: ListTile(leading: Icon(Icons.analytics), title: Text('Report / Analysis'))),
              const PopupMenuItem(value: 'alerts', child: ListTile(leading: Icon(Icons.gpp_maybe), title: Text('Critical alerts'))),
              const PopupMenuItem(value: 'blocked', child: ListTile(leading: Icon(Icons.block), title: Text('Blocked items'))),
              if (_supported)
                PopupMenuItem(
                  value: 'toggle',
                  child: ListTile(
                    leading: Icon(running ? Icons.stop : Icons.play_arrow),
                    title: Text(running ? 'Stop monitoring' : 'Start monitoring'),
                  ),
                ),
              const PopupMenuItem(value: 'clear', child: ListTile(leading: Icon(Icons.delete_sweep), title: Text('Clear list'))),
            ],
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
                final blocked = e.how.startsWith('BLOCKED');
                return ListTile(
                  tileColor: blocked ? Colors.red.withValues(alpha: 0.08) : null,
                  leading: Icon(blocked ? Icons.block : (hit ? Icons.warning_amber : Icons.lock_outline),
                      color: blocked ? Colors.red.shade800 : severityColor(e.severity)),
                  trailing: blocked
                      ? Chip(
                          label: Text('BLOCKED', style: TextStyle(color: Colors.white, fontSize: 12)),
                          backgroundColor: Colors.red.shade800,
                          visualDensity: VisualDensity.compact,
                          padding: EdgeInsets.zero,
                        )
                      : (hit ? SeverityChip(e.severity) : null),
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
