import 'pii_detector.dart';
import 'tracker_classifier.dart';

class TransactionEvent {
  TransactionEvent({
    required this.time,
    required this.who,
    required this.what,
    required this.how,
    required this.destination,
    this.app,
    this.appName,
    this.appPath,
    this.bytesUp = 0,
    this.bytesDown = 0,
    this.duration = Duration.zero,
  });

  final DateTime time;
  final String who; // receiving host (and user-agent for plain HTTP)
  final List<PiiMatch> what; // personal data categories found
  final String how; // e.g. "HTTP POST with body", "HTTPS tunnel (metadata only)"
  final String destination;
  final String? app; // local application making the request, e.g. "chrome.exe (PID 123)"
  final String? appName; // e.g. "chrome.exe"
  final String? appPath; // full executable path when available
  final int bytesUp; // sent to the destination
  final int bytesDown; // received from the destination
  final Duration duration;

  String get host => who.split(' | ').first;
  TrackerInfo? get tracker => TrackerClassifier.classify(host);
  bool get encrypted => how.startsWith('HTTPS');

  // Plain-HTTP exposure is escalated one level because anyone on the path can read it.
  // Known behavioral trackers are at least Low even when no personal data is visible.
  Severity get severity {
    var top = what.isEmpty ? -1 : what.map((m) => m.category.severity.rank).reduce((a, b) => a > b ? a : b);
    if (top >= 0 && !encrypted) top += 1;
    if (tracker != null && top < Severity.low.rank) top = Severity.low.rank;
    if (top < 0) return Severity.info;
    return Severity.values[top.clamp(0, Severity.critical.rank)];
  }

  static String formatBytes(int b) {
    if (b < 1024) return '$b B';
    if (b < 1024 * 1024) return '${(b / 1024).toStringAsFixed(1)} KB';
    return '${(b / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  Map<String, dynamic> toJson() => {
        'time': time.toIso8601String(),
        'severity': severity.name,
        'app': app,
        'appPath': appPath,
        'who': who,
        'how': how,
        'destination': destination,
        'bytesUp': bytesUp,
        'bytesDown': bytesDown,
        'durationMs': duration.inMilliseconds,
        'tracker': tracker == null ? null : {'owner': tracker!.owner, 'category': tracker!.category},
        'what': [
          for (final m in what) {'category': m.category.name, 'value': m.redacted, 'where': m.where}
        ],
      };
}
