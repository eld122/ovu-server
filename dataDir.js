import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Where users.json, social.json, cloud versions and ghosts are stored.
 *
 *  1. OVU_DATA_DIR (explicit)            -> that folder (point it at a PERSISTENT volume)
 *  2. /data exists (Fly / Railway / Render / Docker volume mount convention) -> /data
 *  3. otherwise ./data next to the code  -> fine for local dev, WIPED on ephemeral hosts
 */
const explicit = process.env.OVU_DATA_DIR?.trim();
const volume = !explicit && fs.existsSync("/data") ? "/data" : null;

export const DATA_DIR = explicit || volume || path.join(__dirname, "data");
export const DATA_DIR_PERSISTENT = !!(explicit || volume);

try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.accessSync(DATA_DIR, fs.constants.W_OK);
} catch (err) {
  console.error(`[ovu] DATA_DIR ${DATA_DIR} is not writable:`, err.message);
  process.exit(1);
}

if (process.env.NODE_ENV === "production" && !DATA_DIR_PERSISTENT) {
  console.warn(
    "\n[ovu] WARNING: NODE_ENV=production but no persistent data folder is configured.\n" +
      "      Set OVU_DATA_DIR to a mounted volume (e.g. /data). Otherwise every restart/deploy\n" +
      "      deletes all accounts, cloud versions and social data.\n"
  );
}
console.log(`[ovu] data folder: ${DATA_DIR} (${DATA_DIR_PERSISTENT ? "configured" : "local ./data"})`);
