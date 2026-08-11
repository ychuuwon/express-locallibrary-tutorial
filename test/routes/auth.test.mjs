import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";

import app from "../../app.js";
import {
  authenticate,
  destroySession,
  issueSession,
  resetSessions,
  safeReturnTo,
  sessionMiddleware,
} from "../../middleware/authSession.js";

test("Auth helpers", async (t) => {
  t.afterEach(() => {
    resetSessions();
  });

  await t.test("validates credentials and return paths", async () => {
    assert.equal(authenticate("admin", "admin123")?.username, "admin");
    assert.equal(authenticate("admin", "wrong"), null);
    assert.equal(safeReturnTo("/catalog/books"), "/catalog/books");
    assert.equal(safeReturnTo("//evil.example"), "/catalog");
    assert.equal(safeReturnTo("https://evil.example"), "/catalog");
  });

  await t.test("issues and clears a session cookie", async () => {
    const issuedCookies = [];
    const req = { cookies: {} };
    const res = {
      cookie(name, value) {
        issuedCookies.push({ name, value });
      },
      clearCookie(name) {
        issuedCookies.push({ name, cleared: true });
      },
      locals: {},
    };

    issueSession(res, {
      username: "admin",
      displayName: "Library admin",
    });

    assert.equal(issuedCookies.length, 1);
    assert.equal(issuedCookies[0].name, "locallibrary.sid");
    assert.ok(issuedCookies[0].value);

    req.cookies["locallibrary.sid"] = issuedCookies[0].value;
    destroySession(req, res);

    assert.equal(issuedCookies[1].name, "locallibrary.sid");
    assert.equal(issuedCookies[1].cleared, true);
  });

  await t.test("hydrates req.user from a session cookie", async () => {
    let sessionCookieValue;
    const resForIssue = {
      cookie(name, value) {
        if (name === "locallibrary.sid") {
          sessionCookieValue = value;
        }
      },
      clearCookie() {},
      locals: {},
    };

    issueSession(resForIssue, {
      username: "admin",
      displayName: "Library admin",
    });

    const req = {
      cookies: {
        "locallibrary.sid": sessionCookieValue,
      },
    };
    const res = {
      clearCookie() {},
      locals: {},
    };

    await new Promise((resolve) => sessionMiddleware(req, res, resolve));

    assert.equal(req.user.username, "admin");
    assert.equal(res.locals.isAuthenticated, true);
  });

  await t.test("supports login and logout routes", async () => {
    const agent = request.agent(app);

    const loginResponse = await agent
      .post("/users/login")
      .type("form")
      .send({
        username: "admin",
        password: "admin123",
        returnTo: "/catalog",
      })
      .expect(302)
      .expect("Location", "/catalog");

    assert.ok(loginResponse.headers["set-cookie"]?.length > 0);

    const logoutResponse = await agent
      .post("/users/logout")
      .expect(302)
      .expect("Location", "/catalog");

    assert.ok(logoutResponse.headers["set-cookie"]?.some((value) => value.includes("locallibrary.sid=;")));
  });
});