/// Behavioral-data collectors identified by destination domain.
class TrackerInfo {
  const TrackerInfo(this.owner, this.category);
  final String owner;
  final String category; // Analytics, Advertising, Telemetry, Social tracking, Session replay
}

class TrackerClassifier {
  // Matched by domain suffix. Not exhaustive; extend as needed.
  static const _known = <String, TrackerInfo>{
    'google-analytics.com': TrackerInfo('Google', 'Analytics'),
    'analytics.google.com': TrackerInfo('Google', 'Analytics'),
    'googletagmanager.com': TrackerInfo('Google', 'Analytics'),
    'doubleclick.net': TrackerInfo('Google', 'Advertising'),
    'googlesyndication.com': TrackerInfo('Google', 'Advertising'),
    'googleadservices.com': TrackerInfo('Google', 'Advertising'),
    'facebook.net': TrackerInfo('Meta', 'Social tracking'),
    'connect.facebook.com': TrackerInfo('Meta', 'Social tracking'),
    'graph.facebook.com': TrackerInfo('Meta', 'Social tracking'),
    'pixel.facebook.com': TrackerInfo('Meta', 'Advertising'),
    'ads-twitter.com': TrackerInfo('X / Twitter', 'Advertising'),
    'analytics.twitter.com': TrackerInfo('X / Twitter', 'Analytics'),
    'ads.linkedin.com': TrackerInfo('LinkedIn', 'Advertising'),
    'px.ads.linkedin.com': TrackerInfo('LinkedIn', 'Advertising'),
    'analytics.tiktok.com': TrackerInfo('TikTok', 'Analytics'),
    'ads.tiktok.com': TrackerInfo('TikTok', 'Advertising'),
    'bat.bing.com': TrackerInfo('Microsoft', 'Advertising'),
    'clarity.ms': TrackerInfo('Microsoft', 'Session replay'),
    'vortex.data.microsoft.com': TrackerInfo('Microsoft', 'Telemetry'),
    'telemetry.microsoft.com': TrackerInfo('Microsoft', 'Telemetry'),
    'events.data.microsoft.com': TrackerInfo('Microsoft', 'Telemetry'),
    'self.events.data.microsoft.com': TrackerInfo('Microsoft', 'Telemetry'),
    'amazon-adsystem.com': TrackerInfo('Amazon', 'Advertising'),
    'scorecardresearch.com': TrackerInfo('Comscore', 'Analytics'),
    'quantserve.com': TrackerInfo('Quantcast', 'Advertising'),
    'adnxs.com': TrackerInfo('Xandr', 'Advertising'),
    'criteo.com': TrackerInfo('Criteo', 'Advertising'),
    'criteo.net': TrackerInfo('Criteo', 'Advertising'),
    'taboola.com': TrackerInfo('Taboola', 'Advertising'),
    'outbrain.com': TrackerInfo('Outbrain', 'Advertising'),
    'hotjar.com': TrackerInfo('Hotjar', 'Session replay'),
    'fullstory.com': TrackerInfo('FullStory', 'Session replay'),
    'mixpanel.com': TrackerInfo('Mixpanel', 'Analytics'),
    'segment.io': TrackerInfo('Segment', 'Analytics'),
    'segment.com': TrackerInfo('Segment', 'Analytics'),
    'amplitude.com': TrackerInfo('Amplitude', 'Analytics'),
    'heap.io': TrackerInfo('Heap', 'Analytics'),
    'newrelic.com': TrackerInfo('New Relic', 'Telemetry'),
    'nr-data.net': TrackerInfo('New Relic', 'Telemetry'),
    'sentry.io': TrackerInfo('Sentry', 'Telemetry'),
    'branch.io': TrackerInfo('Branch', 'Analytics'),
    'appsflyer.com': TrackerInfo('AppsFlyer', 'Analytics'),
    'adjust.com': TrackerInfo('Adjust', 'Analytics'),
    'app-measurement.com': TrackerInfo('Google', 'Analytics'),
    'crashlytics.com': TrackerInfo('Google', 'Telemetry'),
    'demdex.net': TrackerInfo('Adobe', 'Advertising'),
    'omtrdc.net': TrackerInfo('Adobe', 'Analytics'),
    'everesttech.net': TrackerInfo('Adobe', 'Advertising'),
    'pubmatic.com': TrackerInfo('PubMatic', 'Advertising'),
    'rubiconproject.com': TrackerInfo('Magnite', 'Advertising'),
    'openx.net': TrackerInfo('OpenX', 'Advertising'),
    'bluekai.com': TrackerInfo('Oracle', 'Advertising'),
    'snapchat.com/tr': TrackerInfo('Snap', 'Advertising'),
    'tr.snapchat.com': TrackerInfo('Snap', 'Advertising'),
  };

  static TrackerInfo? classify(String host) {
    final h = host.toLowerCase();
    for (final e in _known.entries) {
      final k = e.key;
      if (!k.contains('/') && (h == k || h.endsWith('.$k'))) return e.value;
    }
    return null;
  }
}
