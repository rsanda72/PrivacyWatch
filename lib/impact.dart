import 'core/event.dart';

class BlockRecord {
  BlockRecord(this.host, this.app, this.rule, this.time, this.affects, this.impact, this.service);
  final String host;
  final String app;
  final String rule; // which PrivacyWatch rule stopped it
  final DateTime time;
  final String affects; // potential functionality affected
  final int impact; // 0 none, 1 low, 2 medium, 3 high
  final String service;
}

class ImpactGroup {
  ImpactGroup(this.host, this.service, this.affects, this.impact);
  final String host;
  final String service;
  final String affects;
  final int impact;
  final apps = <String>{};
  final rules = <String>{};
  int count = 0;
  DateTime? last;

  bool get repeated => count >= 3;

  /// Plain-language cause and effect.
  String get explanation {
    final who = apps.length == 1 ? apps.first : '${apps.length} apps';
    final base = impact >= 2
        ? '$service may not work properly because PrivacyWatch blocked traffic to $host.'
        : impact == 1
            ? '$service features such as connection checks may fail because $host was blocked.'
            : 'Blocking $host should not break anything you use.';
    return '$base ($who, $count blocked attempt${count == 1 ? '' : 's'}.)'
        '${repeated && impact >= 1 ? ' It keeps failing after being blocked, so PrivacyWatch is a possible root cause. If $service misbehaves, unblock $host.' : ''}';
  }
}

class ImpactSummary {
  ImpactSummary(this.records, this.groups);
  final List<BlockRecord> records;
  final List<ImpactGroup> groups; // most impactful first

  Set<String> get websites => {for (final g in groups) g.host};
  Set<String> get apps => {for (final g in groups) ...g.apps};
  Set<String> get services => {for (final g in groups.where((g) => g.impact >= 1)) g.service};
  List<ImpactGroup> get top => groups.where((g) => g.impact >= 1).take(5).toList();

  static const _services = <String, (String, String, int)>{
    'google.com': ('Google', 'Search, sign-in and pages that load Google content', 3),
    'gstatic.com': ('Google', 'Fonts, images and scripts used by many sites', 3),
    'googleapis.com': ('Google', 'Maps, fonts and sign-in on many sites', 3),
    'youtube.com': ('YouTube', 'Video playback', 3),
    'zoom.us': ('Zoom', 'Meetings and sign-in', 3),
    'onzoom.com': ('Zoom', 'Connectivity tests and meeting setup', 1),
    'microsoft.com': ('Microsoft', 'Updates, sign-in and Office features', 3),
    'live.com': ('Microsoft', 'Account sign-in', 3),
    'windowsupdate.com': ('Windows Update', 'Security updates', 3),
    'cloudflare.com': ('Cloudflare', 'Many websites that rely on it', 2),
    'amazonaws.com': ('Amazon cloud', 'Apps and sites hosted there', 2),
    'apple.com': ('Apple', 'Updates and sign-in', 3),
    'facebook.com': ('Facebook', 'Facebook and Meta sign-in', 2),
  };

  static String _base(String host) {
    final p = host.toLowerCase().split('.');
    return p.length <= 2 ? host.toLowerCase() : p.sublist(p.length - 2).join('.');
  }

  static ImpactSummary build(List<TransactionEvent> events) {
    final records = <BlockRecord>[];
    final groups = <String, ImpactGroup>{};
    for (final e in events.where((e) => e.how.startsWith('BLOCKED'))) {
      final tracker = e.tracker;
      final known = _services[_base(e.host)];
      final (service, affects, impact) = tracker != null
          ? (tracker.owner, 'Only ${tracker.category.toLowerCase()}; pages should still work', 0)
          : known ?? (_base(e.host), 'Unknown. Depends on what this site does for the app', 1);
      final app = (e.app ?? 'unknown app').replaceAll(RegExp(r' \(PID \d+\)'), '');
      final rule = e.how.contains('(application)') ? 'Application blocked' : 'Destination blocked';
      records.add(BlockRecord(e.host, app, rule, e.time, affects, impact, service));
      final g = groups.putIfAbsent(e.host, () => ImpactGroup(e.host, service, affects, impact));
      g.apps.add(app);
      g.rules.add(rule);
      g.count++;
      if (g.last == null || e.time.isAfter(g.last!)) g.last = e.time;
    }
    final list = groups.values.toList()
      ..sort((a, b) {
        final c = b.impact.compareTo(a.impact);
        return c != 0 ? c : b.count.compareTo(a.count);
      });
    return ImpactSummary(records, list);
  }
}
