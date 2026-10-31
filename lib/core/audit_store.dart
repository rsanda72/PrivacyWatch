import 'dart:convert';
import 'dart:io';

/// One destination as it looked when a snapshot was taken.
class AuditItem {
  AuditItem({
    required this.host,
    required this.blocked,
    required this.sent,
    required this.refused,
    this.category,
    this.owner,
    this.severity,
    this.dataTypes = const [],
  });
  final String host;
  final bool blocked; // blocked at snapshot time
  final int sent; // requests that reached it
  final int refused; // requests PrivacyWatch stopped
  final String? category; // tracker category, if it is a known tracker
  final String? owner;
  final String? severity; // worst severity seen, if personal data was involved
  final List<String> dataTypes;

  Map<String, dynamic> toJson() => {
        'host': host,
        'blocked': blocked,
        'sent': sent,
        'refused': refused,
        'category': category,
        'owner': owner,
        'severity': severity,
        'dataTypes': dataTypes,
      };

  static AuditItem fromJson(Map<String, dynamic> j) => AuditItem(
        host: j['host'] as String,
        blocked: j['blocked'] == true,
        sent: (j['sent'] as num?)?.toInt() ?? 0,
        refused: (j['refused'] as num?)?.toInt() ?? 0,
        category: j['category'] as String?,
        owner: j['owner'] as String?,
        severity: j['severity'] as String?,
        dataTypes: ((j['dataTypes'] as List?) ?? const []).cast<String>(),
      );
}

/// The privacy state at one moment: what was seen, what was blocked, and the score.
class AuditSnapshot {
  AuditSnapshot({
    required this.id,
    required this.time,
    required this.score,
    required this.requestsChecked,
    required this.blockedDestinations,
    required this.items,
  });
  final String id;
  final DateTime time;
  final int score;
  final int requestsChecked;
  final int blockedDestinations;
  final List<AuditItem> items;

  Map<String, dynamic> toJson() => {
        'id': id,
        'time': time.toIso8601String(),
        'score': score,
        'requestsChecked': requestsChecked,
        'blockedDestinations': blockedDestinations,
        'items': [for (final i in items) i.toJson()],
      };

  static AuditSnapshot fromJson(Map<String, dynamic> j) => AuditSnapshot(
        id: j['id'] as String,
        time: DateTime.parse(j['time'] as String),
        score: (j['score'] as num).toInt(),
        requestsChecked: (j['requestsChecked'] as num?)?.toInt() ?? 0,
        blockedDestinations: (j['blockedDestinations'] as num?)?.toInt() ?? 0,
        items: [for (final i in (j['items'] as List? ?? const [])) AuditItem.fromJson(i as Map<String, dynamic>)],
      );
}

/// What differs between an earlier and a later snapshot.
class AuditDiff {
  AuditDiff(this.earlier, this.later) {
    final a = {for (final i in earlier.items) i.host: i};
    final b = {for (final i in later.items) i.host: i};
    for (final e in b.entries) {
      final before = a[e.key];
      final now = e.value;
      if (before == null) {
        (now.blocked ? newlySeenBlocked : newlySeenOpen).add(now);
      } else if (!before.blocked && now.blocked) {
        newlyBlocked.add(now);
      } else if (before.blocked && !now.blocked) {
        newlyUnblocked.add(now);
      } else if (!now.blocked && now.sent > 0) {
        stillOpen.add(now);
      } else if (now.blocked) {
        stillBlocked.add(now);
      }
    }
    for (final e in a.entries) {
      if (!b.containsKey(e.key)) notSeenAgain.add(e.value);
    }
  }

  final AuditSnapshot earlier;
  final AuditSnapshot later;
  final newlySeenOpen = <AuditItem>[]; // new, and getting through
  final newlySeenBlocked = <AuditItem>[]; // new, but already blocked
  final newlyBlocked = <AuditItem>[];
  final newlyUnblocked = <AuditItem>[];
  final stillOpen = <AuditItem>[];
  final stillBlocked = <AuditItem>[];
  final notSeenAgain = <AuditItem>[];

  int get scoreChange => later.score - earlier.score;
}

/// Audit snapshots, kept in the app's own data store (audit.json) so they survive restarts.
class AuditStore {
  AuditStore._();
  static final AuditStore instance = AuditStore._();

  File? _file;
  final _snapshots = <AuditSnapshot>[];

  /// Newest first.
  List<AuditSnapshot> get snapshots => List.unmodifiable(_snapshots.reversed);

  void attach(File file) {
    if (_file?.path == file.path) return;
    _file = file;
    _snapshots.clear();
    try {
      if (file.existsSync()) {
        final j = jsonDecode(file.readAsStringSync()) as List;
        _snapshots.addAll(j.map((e) => AuditSnapshot.fromJson(e as Map<String, dynamic>)));
      }
    } catch (_) {}
  }

  AuditSnapshot add({
    required int score,
    required int requestsChecked,
    required int blockedDestinations,
    required List<AuditItem> items,
  }) {
    final now = DateTime.now();
    String two(int n) => n.toString().padLeft(2, '0');
    var id = 'PW-${now.year}${two(now.month)}${two(now.day)}-${two(now.hour)}${two(now.minute)}${two(now.second)}';
    var n = 1;
    final base = id;
    while (_snapshots.any((x) => x.id == id)) {
      id = '$base-${++n}';
    }
    final s = AuditSnapshot(
      id: id,
      time: now,
      score: score,
      requestsChecked: requestsChecked,
      blockedDestinations: blockedDestinations,
      items: items,
    );
    _snapshots.add(s);
    _persist();
    return s;
  }

  void delete(String id) {
    _snapshots.removeWhere((s) => s.id == id);
    _persist();
  }

  void clearAll() {
    _snapshots.clear();
    _persist();
  }

  void _persist() {
    try {
      _file?.writeAsStringSync(jsonEncode([for (final s in _snapshots) s.toJson()]));
    } catch (_) {}
  }
}
