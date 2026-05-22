/**
 * Supertest helpers for GitDock API (localhost + CSRF header).
 */
const request = require("supertest");

const API_HEADERS = { "x-gitdock": "1", "Content-Type": "application/json" };

function api(app) {
  const agent = request(app);
  return {
    get: (url) => agent.get(url).set("Host", "127.0.0.1"),
    post: (url, body) => agent.post(url).set(API_HEADERS).set("Host", "127.0.0.1").send(body),
    put: (url, body) => agent.put(url).set(API_HEADERS).set("Host", "127.0.0.1").send(body),
    del: (url) => agent.delete(url).set(API_HEADERS).set("Host", "127.0.0.1"),
  };
}

module.exports = { api, API_HEADERS };
