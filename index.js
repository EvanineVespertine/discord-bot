import express from "express";
import nacl from "tweetnacl";

const app = express();

// Keep raw body for verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// place for public key
const PUBLIC_KEY = "87c89bbfdf3ab72c13da9a9a404f4af42d48dd877336ab937e29ab850204ebb0";

function verifyDiscordRequest(req) {
  const signature = req.get("X-Signature-Ed25519");
  const timestamp = req.get("X-Signature-Timestamp");

  if (!signature || !timestamp) return false;

  const isValid = nacl.sign.detached.verify(
    Buffer.from(timestamp + req.rawBody),
    Buffer.from(signature, "hex"),
    Buffer.from(PUBLIC_KEY, "hex")
  );

  return isValid;
}

app.post("/interactions", (req, res) => {

  if (!verifyDiscordRequest(req)) {
    console.log("Invalid request signature");
    return res.status(401).send("Bad request signature");
  }

  const { type, data } = req.body;

  // Discord URL verification ping
  if (type === 1) {
    console.log("Discord verified endpoint");
    return res.json({ type: 1 });
  }

  // /ping command
  if (type === 2 && data.name === "ping") {
    console.log("🏓Ping received");
    return res.json({
      type: 4,
      data: { content: "pong" },
    });
  }

  res.sendStatus(400);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bot listening on port ${PORT}`));
