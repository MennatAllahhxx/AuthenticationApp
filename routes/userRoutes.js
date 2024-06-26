const express = require('express');

const usersController = require("../controllers/usersController");
const verifyJWT = require("../middleware/verifyJWT");

const router = express.Router();

router.use(verifyJWT);
router.route("/").get(usersController.getAllUsers);

module.exports = router;