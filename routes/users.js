const express = require("express");
const {
  authenticate,
  destroySession,
  issueSession,
  safeReturnTo,
} = require("../middleware/authSession");

const router = express.Router();

/* GET users listing. */
router.get("/", function (req, res) {
  res.redirect("/users/login");
});

router.get("/login", function (req, res) {
  res.render("login", {
    title: "Sign in",
    error: null,
    username: "",
    returnTo: safeReturnTo(req.query.returnTo),
  });
});

router.post("/login", function (req, res) {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";
  const returnTo = safeReturnTo(req.body.returnTo);
  const user = authenticate(username, password);

  if (!user) {
    return res.status(401).render("login", {
      title: "Sign in",
      error: "Invalid username or password.",
      username,
      returnTo,
    });
  }

  issueSession(res, user);
  res.redirect(returnTo);
});

router.post("/logout", function (req, res) {
  destroySession(req, res);
  res.redirect("/catalog");
});

module.exports = router;