import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import 'core/event.dart';

class TrendPoint {
  TrendPoint(this.time, this.bytes, this.blocked);
  final DateTime time;
  final int bytes; // up + down actually transferred
  final bool blocked;
}

enum TrendVerdict { positive, neutral, negative, notEnough }

class TrafficTrend {
  TrafficTrend._(this.buckets, this.start, this.end, this.earlier, this.recent, this.verdict, this.change,
      this.blockedRecent, this.blockedEarlier);

  final List<int> buckets;
  final DateTime start;
  final DateTime end;
  final int earlier; // bytes in the first half of the period
  final int recent; // bytes in the second half
  final TrendVerdict verdict;
  final double change; // fraction, e.g. -0.3 = 30% less traffic
  final int blockedEarlier;
  final int blockedRecent;

  static const bucketCount = 12;
  static const neutralBand = 0.10; // changes within +/-10% count as no change

  static TrafficTrend compute(List<TrendPoint> points) {
    if (points.length < 2) return _empty();
    final sorted = [...points]..sort((a, b) => a.time.compareTo(b.time));
    final start = sorted.first.time, end = sorted.last.time;
    final span = end.difference(start);
    if (span < const Duration(seconds: 30)) return _empty(start: start, end: end);
    final width = span.inMicroseconds / bucketCount;
    final buckets = List<int>.filled(bucketCount, 0);
    final mid = start.add(span ~/ 2);
    var earlier = 0, recent = 0, blockedE = 0, blockedR = 0;
    for (final p in sorted) {
      final i = ((p.time.difference(start).inMicroseconds) / width).floor().clamp(0, bucketCount - 1);
      buckets[i] += p.bytes;
      final isEarlier = p.time.isBefore(mid);
      if (isEarlier) {
        earlier += p.bytes;
        if (p.blocked) blockedE++;
      } else {
        recent += p.bytes;
        if (p.blocked) blockedR++;
      }
    }
    final double change;
    if (earlier == 0) {
      change = recent == 0 ? 0 : 1;
    } else {
      change = (recent - earlier) / earlier;
    }
    final verdict = change.abs() <= neutralBand
        ? TrendVerdict.neutral
        : (change < 0 ? TrendVerdict.positive : TrendVerdict.negative);
    return TrafficTrend._(buckets, start, end, earlier, recent, verdict, change, blockedR, blockedE);
  }

  static TrafficTrend _empty({DateTime? start, DateTime? end}) => TrafficTrend._(
      List.filled(bucketCount, 0), start ?? DateTime.now(), end ?? DateTime.now(), 0, 0, TrendVerdict.notEnough, 0, 0, 0);

  /// Reads every saved capture (current and rotated logs) so the trend covers more than this session.
  static List<TrendPoint> loadHistory(Directory dir) {
    final out = <TrendPoint>[];
    if (!dir.existsSync()) return out;
    for (final f in dir.listSync().whereType<File>()) {
      final name = f.uri.pathSegments.last;
      if (!name.startsWith('transactions') || !name.endsWith('.jsonl')) continue;
      try {
        for (final line in f.readAsLinesSync()) {
          if (line.trim().isEmpty) continue;
          try {
            final j = jsonDecode(line) as Map<String, dynamic>;
            final how = (j['how'] as String?) ?? '';
            out.add(TrendPoint(
              DateTime.parse(j['time'] as String),
              ((j['bytesUp'] as num?) ?? 0).toInt() + ((j['bytesDown'] as num?) ?? 0).toInt(),
              how.startsWith('BLOCKED'),
            ));
          } catch (_) {}
        }
      } catch (_) {}
    }
    return out;
  }
}

class TrafficTrendPanel extends StatelessWidget {
  const TrafficTrendPanel({super.key, required this.dataDir, this.compact = false});
  final Directory dataDir;
  final bool compact; // one-line version for the main Traffic card

  static String _span(Duration d) {
    if (d.inDays >= 2) return '${d.inDays} days';
    if (d.inHours >= 2) return '${d.inHours} hours';
    if (d.inMinutes >= 2) return '${d.inMinutes} minutes';
    return '${d.inSeconds} seconds';
  }

  @override
  Widget build(BuildContext context) {
    final t = TrafficTrend.compute(TrafficTrend.loadHistory(dataDir));
    final theme = Theme.of(context);
    final (Color color, IconData icon, String title, String text) = switch (t.verdict) {
      TrendVerdict.positive => (
          Colors.green,
          Icons.trending_down,
          'Positive: traffic is down ${(t.change.abs() * 100).round()}%',
          'Less data is flowing than earlier in this period. This is the effect you want from blocking.'
        ),
      TrendVerdict.negative => (
          Colors.red,
          Icons.trending_up,
          'Negative: traffic is up ${t.earlier == 0 ? '' : '${(t.change * 100).round()}%'}',
          'More data is flowing than earlier in this period. Check which apps and destinations grew.'
        ),
      TrendVerdict.neutral => (
          Colors.blueGrey,
          Icons.trending_flat,
          'Neutral: no real change in traffic',
          'Traffic is within 10% of the earlier half of the period.'
        ),
      TrendVerdict.notEnough => (
          Colors.grey,
          Icons.hourglass_empty,
          'Not enough history yet',
          'Keep monitoring. A trend needs at least 30 seconds of captured traffic.'
        ),
    };
    final peak = t.buckets.fold<int>(0, (a, b) => a > b ? a : b);
    if (compact) {
      final short = switch (t.verdict) {
        TrendVerdict.positive => 'Down ${(t.change.abs() * 100).round()}% - positive',
        TrendVerdict.negative => t.earlier == 0 ? 'Up - negative' : 'Up ${(t.change * 100).round()}% - negative',
        TrendVerdict.neutral => 'No real change - neutral',
        TrendVerdict.notEnough => 'Not enough history yet',
      };
      return Container(
        padding: const EdgeInsets.all(6),
        decoration: BoxDecoration(color: color.withValues(alpha: 0.1), borderRadius: BorderRadius.circular(6)),
        child: Row(children: [
          Icon(icon, color: color, size: 22),
          const SizedBox(width: 6),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('Trend: $short', style: theme.textTheme.labelLarge?.copyWith(color: color)),
              Text('Relative to how much you use your device', style: theme.textTheme.labelSmall),
            ]),
          ),
          if (t.verdict != TrendVerdict.notEnough)
            SizedBox(
              width: 90,
              height: 28,
              child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
                for (var i = 0; i < t.buckets.length; i++)
                  Expanded(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 0.5),
                      child: Container(
                        height: peak == 0 ? 2 : 2 + 26 * t.buckets[i] / peak,
                        color: i < t.buckets.length ~/ 2 ? color.withValues(alpha: 0.45) : color,
                      ),
                    ),
                  ),
              ]),
            ),
        ]),
      );
    }
    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(icon, color: color),
            const SizedBox(width: 6),
            Expanded(child: Text(title, style: theme.textTheme.titleSmall?.copyWith(color: color))),
          ]),
          const SizedBox(height: 4),
          Text(text),
          if (t.verdict != TrendVerdict.notEnough) ...[
            const SizedBox(height: 8),
            SizedBox(
              height: 60,
              child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
                for (var i = 0; i < t.buckets.length; i++)
                  Expanded(
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 1),
                      child: Tooltip(
                        message: TransactionEvent.formatBytes(t.buckets[i]),
                        child: Container(
                          height: peak == 0 ? 2 : 2 + 58 * t.buckets[i] / peak,
                          color: i < t.buckets.length ~/ 2 ? color.withValues(alpha: 0.45) : color,
                        ),
                      ),
                    ),
                  ),
              ]),
            ),
            const SizedBox(height: 4),
            Text(
              'Last ${_span(t.end.difference(t.start))}: earlier half ${TransactionEvent.formatBytes(t.earlier)}, '
              'recent half ${TransactionEvent.formatBytes(t.recent)}. '
              'Requests blocked: ${t.blockedEarlier} earlier, ${t.blockedRecent} recent.',
              style: theme.textTheme.bodySmall,
            ),
          ],
          const SizedBox(height: 6),
          Text(
            'Read this with care: traffic naturally rises and falls with how much you use your device. '
            'A lower trend can just mean you were less active, and a higher one that you were busier. '
            'Blocked requests transfer no data, so they show up as the blocked counts above.',
            style: theme.textTheme.bodySmall?.copyWith(fontStyle: FontStyle.italic),
          ),
        ]),
      ),
    );
  }
}
