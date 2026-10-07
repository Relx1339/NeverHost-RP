const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'db.json');
const API_DATA = path.join(__dirname, 'api-data');

function readCaptured(name, fallback) {
  try {
    const raw = fs.readFileSync(path.join(API_DATA, name), 'utf8');
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

class DB {
  constructor() {
    if (fs.existsSync(DB_FILE)) {
      const loaded = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
      this.data = { ...this.seed(), ...loaded };
    } else {
      this.data = this.seed();
      this.save();
    }
  }

  seed() {
    const eventsResp = readCaptured('_api_events_page=1_limit=9.json', { events: [], total: 0 });
    return {
      users: [],
      sessions: [],
      whitelistApplications: [],
      tickets: [],
      vacations: [],
      servers: readCaptured('_api_servers.json', []),
      events: eventsResp.events || [],
      partners: readCaptured('_api_partners.json', []),
      team: readCaptured('_api_team.json', []),
      faq: readCaptured('_api_faq.json', []),
      gallery: readCaptured('_api_gallery.json', []),
      roster: readCaptured('_api_roster.json', []),
      streamStats: readCaptured('_api_stream-stats.json', []),
      liveStreams: readCaptured('_api_live-streams.json', []),
      careers: readCaptured('api_careers.json', []),
      gameRanks: readCaptured('api_game-ranks_serverId_1.json', []),
      stats: readCaptured('_api_stats.json', {
        players: 0,
        discordMembers: 0,
        discordOnline: 0,
        discordServers: [],
        xCommunity: {},
        communityFollowers: '0',
        monthlyViews: '0',
        watchHours: '0',
      }),
      leaderboard: readCaptured('_api_leaderboard_period=all.json', {
        config: {},
        currentPeriod: '',
        periods: [],
        snapshot: {},
      }),
      siteSettings: {
        hero: readCaptured('_api_site-settings_hero.json', {}),
        social: readCaptured('_api_site-settings_social.json', { socialLinks: {} }),
        countdown: readCaptured('_api_site-settings_countdown.json', { enabled: false }),
        doomTimer: readCaptured('_api_site-settings_doom-timer.json', { enabled: false }),
        endSession: readCaptured('_api_site-settings_end-session.json', { enabled: false }),
        season8: readCaptured('_api_site-settings_season8.json', { enabled: false }),
      },
      localizations: readCaptured('_api_localizations.json', {}),
      visitCounter: 1000000,
    };
  }

  save() {
    fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2));
  }

  col(name) {
    return this.data[name];
  }

  addUser(user) {
    this.data.users.push(user);
    this.save();
  }

  findByUsername(username) {
    return this.data.users.find((u) => u.username.toLowerCase() === String(username).toLowerCase());
  }

  findByUid(uid) {
    return this.data.users.find((u) => u.uid === uid);
  }

  createSession(token, uid) {
    this.data.sessions.push({ token, uid, createdAt: Date.now() });
    this.save();
    return token;
  }

  sessionUser(token) {
    const s = this.data.sessions.find((x) => x.token === token);
    if (!s) return null;
    return this.data.users.find((u) => u.uid === s.uid) || null;
  }

  nextUid() {
    return 'usr_' + Math.random().toString(36).slice(2, 10);
  }
}

module.exports = { DB };
