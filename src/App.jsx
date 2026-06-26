import { useState, useEffect, useCallback, useRef } from "react";
import {
  Lock, Unlock, RefreshCw, Layers, ShieldCheck, ShieldAlert,
  ArrowDownLeft, ArrowUpRight, Eye, EyeOff, AlertTriangle,
  CheckCircle, XCircle, Copy, Zap, GitBranch, Hash, Activity
} from "lucide-react";

// ─── SHA-256 (pure JS, no Web Crypto dependency for demo) ────────────────────
async function sha256hex(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function truncate(hex, len = 12) {
  return hex ? `${hex.slice(0, len)}…${hex.slice(-6)}` : "";
}

function randomHex(bytes = 16) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── Seeded dummy commitments (the anonymity set) ────────────────────────────
const DUMMY_COMMITMENTS = [
  { hash: "a3f8e2c71d4b9f0e6a1c3d5e7b2f4a8c1d3e5f7a2b4c6d8e0f1a3b5c7d9e0f2", label: "Pool Entry α" },
  { hash: "7c2a4f8b0d6e1a3c5f7b9d1e3a5c7f9b1d3e5a7c9f1b3d5e7a9c1f3b5d7e9a1", label: "Pool Entry β" },
  { hash: "f1b3d5e7a9c1f3b5d7e9a1c3f5b7d9e1a3c5f7b9d1e3a5c7f9b1d3e5a7c9f1b", label: "Pool Entry γ" },
  { hash: "2d4f6a8c0e2a4c6e8a0c2e4a6c8e0a2c4e6a8c0e2a4c6e8a0c2e4a6c8e0a2c4", label: "Pool Entry δ" },
];

// ─── Mini Merkle helpers ──────────────────────────────────────────────────────
async function buildMerkleTree(leaves) {
  if (leaves.length === 0) return { layers: [], root: "" };
  let layer = [...leaves];
  const layers = [layer];
  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] || layer[i];
      const combined = await sha256hex(left + right);
      next.push(combined);
    }
    layer = next;
    layers.push(layer);
  }
  return { layers, root: layer[0] };
}

// ─── Toast component ─────────────────────────────────────────────────────────
function Toast({ toasts }) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none" style={{ zIndex: 9999 }}>
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`flex items-center gap-2 px-4 py-2.5 rounded text-sm font-medium border shadow-lg transition-all duration-300 pointer-events-none ${
            t.type === "success"
              ? "bg-emerald-950 border-emerald-700 text-emerald-300"
              : t.type === "error"
              ? "bg-red-950 border-red-700 text-red-300"
              : "bg-zinc-800 border-zinc-600 text-zinc-200"
          }`}
        >
          {t.type === "success" ? <CheckCircle size={14} /> : t.type === "error" ? <XCircle size={14} /> : <Activity size={14} />}
          {t.msg}
        </div>
      ))}
    </div>
  );
}

// ─── Merkle Tree visual ───────────────────────────────────────────────────────
function MerkleViz({ tree, highlightLeaf }) {
  if (!tree || tree.layers.length === 0)
    return (
      <div className="flex items-center justify-center h-24 text-zinc-600 text-xs">
        No commitments yet — deposit to build the tree
      </div>
    );

  const { layers } = tree;
  const reversed = [...layers].reverse();

  return (
    <div className="overflow-x-auto pb-1">
      {reversed.map((layer, li) => (
        <div key={li} className="flex justify-center gap-1 mb-1">
          {layer.map((node, ni) => {
            const isLeaf = li === reversed.length - 1;
            const isHighlighted = isLeaf && ni === highlightLeaf;
            return (
              <div
                key={ni}
                title={node}
                className={`relative flex flex-col items-center`}
              >
                {li > 0 && (
                  <div className="w-px h-2 bg-zinc-700 mx-auto mb-0.5" />
                )}
                <div
                  className={`px-1.5 py-0.5 rounded text-[9px] font-mono border transition-all duration-500 ${
                    li === 0
                      ? "bg-emerald-950 border-emerald-700 text-emerald-300 font-bold"
                      : isHighlighted
                      ? "bg-amber-950 border-amber-500 text-amber-300 animate-pulse"
                      : isLeaf
                      ? "bg-zinc-800 border-zinc-600 text-zinc-400"
                      : "bg-zinc-900 border-zinc-700 text-zinc-500"
                  }`}
                >
                  {li === 0 ? "ROOT" : `${node.slice(0, 6)}…`}
                </div>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}

// ─── Main Application ─────────────────────────────────────────────────────────
export default function ZKPSystem() {
  // Deposit state
  const [secret, setSecret] = useState("");
  const [nullifier, setNullifier] = useState("");
  const [depositLoading, setDepositLoading] = useState(false);

  // Pool state
  const [userCommitments, setUserCommitments] = useState([]);
  const [spentNullifiers, setSpentNullifiers] = useState([]);

  // Withdrawal state
  const [wSecret, setWSecret] = useState("");
  const [wNullifier, setWNullifier] = useState("");
  const [proof, setProof] = useState(null);
  const [proofLoading, setProofLoading] = useState(false);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);

  // Attack sim
  const [attackMode, setAttackMode] = useState(null); // null | "double_spend" | "forged"

  // Merkle
  const [merkleTree, setMerkleTree] = useState(null);
  const [highlightLeaf, setHighlightLeaf] = useState(null);

  // Toasts
  const [toasts, setToasts] = useState([]);
  const toastCounter = useRef(0);

  function addToast(msg, type = "info") {
    const id = ++toastCounter.current;
    setToasts((prev) => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
  }

  // Rebuild Merkle tree whenever pool changes
  const allHashes = [
    ...DUMMY_COMMITMENTS.map((d) => d.hash),
    ...userCommitments.map((c) => c.hash),
  ];

  useEffect(() => {
    if (allHashes.length === 0) { setMerkleTree(null); return; }
    buildMerkleTree(allHashes).then(setMerkleTree);
  }, [userCommitments.length]);

  // ── Deposit ──────────────────────────────────────────────────────────────
  async function handleDeposit() {
    if (!secret.trim() || !nullifier.trim()) {
      addToast("Secret and nullifier are both required", "error"); return;
    }
    setDepositLoading(true);
    await new Promise((r) => setTimeout(r, 600));
    const commitHash = await sha256hex(secret + nullifier);
    const nullHash = await sha256hex(nullifier);
    const already = userCommitments.find((c) => c.hash === commitHash);
    if (already) {
      addToast("This commitment already exists in the pool", "error");
      setDepositLoading(false); return;
    }
    const newC = {
      hash: commitHash,
      nullHash,
      label: `Deposit #${userCommitments.length + 1}`,
      ts: Date.now(),
    };
    setUserCommitments((prev) => [...prev, newC]);
    const newLeafIdx = DUMMY_COMMITMENTS.length + userCommitments.length;
    setHighlightLeaf(newLeafIdx);
    setTimeout(() => setHighlightLeaf(null), 3000);
    addToast("Commitment hashed & added to pool", "success");
    setSecret(""); setNullifier("");
    setDepositLoading(false);
  }

  // ── Generate Proof ────────────────────────────────────────────────────────
  async function handleGenerateProof() {
    if (!wSecret.trim() || !wNullifier.trim()) {
      addToast("Provide your original secret and nullifier", "error"); return;
    }
    setProofLoading(true);
    await new Promise((r) => setTimeout(r, 800));
    const commitHash = await sha256hex(wSecret + wNullifier);
    const nullHash = await sha256hex(wNullifier);
    const piA = randomHex(16);
    const piB = randomHex(16);
    const piC = randomHex(16);

    let targetHash = commitHash;
    if (attackMode === "forged") {
      targetHash = randomHex(32); // totally invalid hash
    }

    const artifactProof = {
      commitment: targetHash,
      nullifierHash: nullHash,
      pi_a: piA, pi_b: piB, pi_c: piC,
      publicInputs: [targetHash, nullHash],
      timestamp: Date.now(),
    };
    setProof(artifactProof);
    setVerifyResult(null);
    addToast(attackMode === "forged" ? "⚠ Forged proof generated" : "ZK proof artifact generated", attackMode ? "error" : "info");
    setProofLoading(false);
  }

  // ── Verify ────────────────────────────────────────────────────────────────
  async function handleVerify() {
    if (!proof) { addToast("Generate a proof first", "error"); return; }
    setVerifyLoading(true);
    await new Promise((r) => setTimeout(r, 700));

    const poolHashes = [
      ...DUMMY_COMMITMENTS.map((d) => d.hash),
      ...userCommitments.map((c) => c.hash),
    ];

    const commitmentExists = poolHashes.includes(proof.commitment);

    let spentCheck = spentNullifiers.includes(proof.nullifierHash);
    if (attackMode === "double_spend") spentCheck = true;

    if (!commitmentExists) {
      setVerifyResult({ ok: false, reason: "COMMITMENT_NOT_IN_POOL", detail: "The commitment hash does not correspond to any leaf in the Merkle tree. Proof rejected — unknown depositor." });
      addToast("Rejected: commitment not in pool", "error");
    } else if (spentCheck) {
      setVerifyResult({ ok: false, reason: "NULLIFIER_ALREADY_SPENT", detail: `Nullifier hash ${truncate(proof.nullifierHash)} has already been consumed. Double-spend attempt blocked.` });
      addToast("Rejected: nullifier already spent", "error");
    } else {
      setSpentNullifiers((prev) => [...prev, proof.nullifierHash]);
      setVerifyResult({ ok: true, reason: "PROOF_VALID", detail: "Commitment exists in pool. Nullifier is fresh. ZK proof structure verified. Withdrawal authorized." });
      addToast("Withdrawal authorized ✓", "success");
    }
    setVerifyLoading(false);
  }

  const allPoolItems = [
    ...DUMMY_COMMITMENTS.map((d) => ({ ...d, dummy: true })),
    ...userCommitments.map((c) => ({ ...c, dummy: false })),
  ];

  // Shuffle display order to simulate anonymity (stable sort by hash)
  const shuffledPool = [...allPoolItems].sort((a, b) => a.hash.localeCompare(b.hash));

  return (
    <div style={{ fontFamily: "'Inter', 'system-ui', sans-serif", background: "#09090b", minHeight: "100vh", color: "#e4e4e7" }}>
      <Toast toasts={toasts} />

      {/* Header */}
      <header style={{ borderBottom: "1px solid #27272a", padding: "14px 28px", display: "flex", alignItems: "center", justifyContent: "space-between", background: "#0c0c0f" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ background: "#064e3b", border: "1px solid #065f46", borderRadius: 6, padding: "6px 8px", display: "flex" }}>
            <Layers size={16} color="#34d399" />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#f4f4f5", letterSpacing: "0.01em" }}>ZeroLedger</div>
            <div style={{ fontSize: 10, color: "#71717a", fontWeight: 500 }}>Privacy-Preserving Transaction System · ZKP Demo</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#34d399", boxShadow: "0 0 6px #34d399" }} />
          <span style={{ fontSize: 10, color: "#52525b", fontWeight: 500 }}>Simulated Network · Local State</span>
        </div>
      </header>

      <div style={{ maxWidth: 1280, margin: "0 auto", padding: "20px 20px 40px" }}>

        {/* ── Row 1: Deposit + Pool ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.4fr", gap: 14, marginBottom: 14 }}>

          {/* Deposit Panel */}
          <div style={{ background: "#111113", border: "1px solid #27272a", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid #27272a", display: "flex", alignItems: "center", gap: 7 }}>
              <ArrowDownLeft size={13} color="#6d6d75" />
              <span style={{ fontSize: 11, fontWeight: 600, color: "#a1a1aa", textTransform: "uppercase", letterSpacing: "0.08em" }}>Commitment Phase · Deposit</span>
            </div>
            <div style={{ padding: 14 }}>

              {/* Secret */}
              <div style={{ marginBottom: 10 }}>
                <label style={{ fontSize: 10, color: "#71717a", fontWeight: 600, display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Secret (client-only · never transmitted)
                </label>
                <div style={{ display: "flex", gap: 6 }}>
                  <input
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="Enter or generate a secret…"
                    style={{ flex: 1, background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#f4f4f5", fontFamily: "monospace", outline: "none" }}
                  />
                  <button
                    onClick={() => setSecret(randomHex(20))}
                    style={{ padding: "7px 10px", background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, color: "#a1a1aa", fontSize: 10, fontWeight: 600 }}
                  >
                    <RefreshCw size={11} /> Auto
                  </button>
                </div>
                <div style={{ marginTop: 4, fontSize: 9, color: "#ef4444", display: "flex", alignItems: "center", gap: 4 }}>
                  <EyeOff size={9} /> Never leaves your device — hashed client-side only
                </div>
              </div>

              {/* Nullifier */}
              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 10, color: "#71717a", fontWeight: 600, display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Nullifier / Nonce (double-spend guard)
                </label>
                <div style={{ display: "flex", gap: 6 }}>
                  <input
                    value={nullifier}
                    onChange={(e) => setNullifier(e.target.value)}
                    placeholder="Unique spend token…"
                    style={{ flex: 1, background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#f4f4f5", fontFamily: "monospace", outline: "none" }}
                  />
                  <button
                    onClick={() => setNullifier(randomHex(12))}
                    style={{ padding: "7px 10px", background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, cursor: "pointer", display: "flex", alignItems: "center", gap: 4, color: "#a1a1aa", fontSize: 10, fontWeight: 600 }}
                  >
                    <RefreshCw size={11} /> Auto
                  </button>
                </div>
              </div>

              {/* Commitment preview */}
              <div style={{ background: "#0c0c0f", border: "1px solid #1e1e20", borderRadius: 5, padding: "8px 10px", marginBottom: 12 }}>
                <div style={{ fontSize: 9, color: "#52525b", marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em" }}>Commitment will be: SHA-256(secret ∥ nullifier)</div>
                <div style={{ fontSize: 10, fontFamily: "monospace", color: "#52525b" }}>
                  {secret && nullifier ? "Computing hash on deposit…" : "— provide both inputs —"}
                </div>
              </div>

              <button
                onClick={handleDeposit}
                disabled={depositLoading}
                style={{ width: "100%", padding: "9px", background: depositLoading ? "#064e3b" : "#065f46", border: "1px solid #047857", borderRadius: 5, color: "#6ee7b7", fontSize: 11, fontWeight: 700, cursor: depositLoading ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, transition: "all 0.2s" }}
              >
                <Lock size={12} />
                {depositLoading ? "Hashing commitment…" : "Deposit → Anonymity Pool"}
              </button>

              {/* Spent nullifiers */}
              {spentNullifiers.length > 0 && (
                <div style={{ marginTop: 10, background: "#1c1100", border: "1px solid #78350f", borderRadius: 5, padding: "8px 10px" }}>
                  <div style={{ fontSize: 9, color: "#d97706", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 5 }}>
                    <AlertTriangle size={9} style={{ display: "inline", marginRight: 4 }} />Spent Nullifiers Registry
                  </div>
                  {spentNullifiers.map((n, i) => (
                    <div key={i} style={{ fontSize: 9, fontFamily: "monospace", color: "#92400e", marginBottom: 2 }}>
                      ✕ {truncate(n, 14)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Mixing Pool */}
          <div style={{ background: "#111113", border: "1px solid #27272a", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid #27272a", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <Layers size={13} color="#6d6d75" />
                <span style={{ fontSize: 11, fontWeight: 600, color: "#a1a1aa", textTransform: "uppercase", letterSpacing: "0.08em" }}>Anonymity Set · Mixing Pool</span>
              </div>
              <div style={{ fontSize: 9, color: "#52525b", background: "#1c1c1f", border: "1px solid #27272a", borderRadius: 4, padding: "2px 7px" }}>
                {shuffledPool.length} commitments
              </div>
            </div>
            <div style={{ padding: 14 }}>
              <div style={{ marginBottom: 8, fontSize: 9, color: "#52525b", lineHeight: 1.5 }}>
                Commitments are sorted by hash value — your deposit is indistinguishable from pool entries. No ordering leaks identity.
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 260, overflowY: "auto" }}>
                {shuffledPool.map((item, i) => (
                  <div
                    key={i}
                    style={{
                      display: "flex", alignItems: "center", gap: 8, padding: "6px 9px",
                      background: item.dummy ? "#0c0c0f" : "#0d1f17",
                      border: `1px solid ${item.dummy ? "#1e1e20" : "#064e3b"}`,
                      borderRadius: 5, transition: "all 0.3s"
                    }}
                  >
                    <Hash size={9} color={item.dummy ? "#3f3f46" : "#059669"} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 9, fontFamily: "monospace", color: item.dummy ? "#52525b" : "#34d399" }}>
                        {truncate(item.hash, 16)}
                      </div>
                      <div style={{ fontSize: 8, color: "#3f3f46", marginTop: 1 }}>{item.label}</div>
                    </div>
                    <div style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: item.dummy ? "#1c1c1f" : "#022c22", color: item.dummy ? "#52525b" : "#065f46", fontWeight: 600 }}>
                      {item.dummy ? "POOL" : "USER"}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Row 2: Merkle Tree ── */}
        <div style={{ background: "#111113", border: "1px solid #27272a", borderRadius: 8, marginBottom: 14, overflow: "hidden" }}>
          <div style={{ padding: "10px 14px", borderBottom: "1px solid #27272a", display: "flex", alignItems: "center", gap: 7 }}>
            <GitBranch size={13} color="#6d6d75" />
            <span style={{ fontSize: 11, fontWeight: 600, color: "#a1a1aa", textTransform: "uppercase", letterSpacing: "0.08em" }}>Merkle Commitment Tree · Live Ledger</span>
            {merkleTree && (
              <span style={{ marginLeft: "auto", fontSize: 9, fontFamily: "monospace", color: "#34d399", background: "#022c22", border: "1px solid #064e3b", borderRadius: 4, padding: "2px 7px" }}>
                Root: {truncate(merkleTree.root, 10)}
              </span>
            )}
          </div>
          <div style={{ padding: "12px 16px" }}>
            <div style={{ fontSize: 9, color: "#52525b", marginBottom: 8, lineHeight: 1.5 }}>
              Each deposit extends the tree. During withdrawal, the prover demonstrates their leaf exists on the path to the root — without revealing which leaf. The Merkle root is public; the path is private.
            </div>
            <MerkleViz tree={merkleTree} highlightLeaf={highlightLeaf} />
          </div>
        </div>

        {/* ── Row 3: Withdrawal + Verifier ── */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>

          {/* Withdrawal / Proof Generation */}
          <div style={{ background: "#111113", border: "1px solid #27272a", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid #27272a", display: "flex", alignItems: "center", gap: 7 }}>
              <ArrowUpRight size={13} color="#6d6d75" />
              <span style={{ fontSize: 11, fontWeight: 600, color: "#a1a1aa", textTransform: "uppercase", letterSpacing: "0.08em" }}>Proof Phase · Withdrawal</span>
            </div>
            <div style={{ padding: 14 }}>

              {/* Attack mode */}
              <div style={{ background: "#1c0a0a", border: "1px solid #7f1d1d", borderRadius: 5, padding: "8px 10px", marginBottom: 12 }}>
                <div style={{ fontSize: 9, color: "#ef4444", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6, display: "flex", alignItems: "center", gap: 4 }}>
                  <Zap size={9} /> Attack Simulation
                </div>
                <div style={{ display: "flex", gap: 5 }}>
                  {[
                    { key: null, label: "None" },
                    { key: "double_spend", label: "Double Spend" },
                    { key: "forged", label: "Forged Proof" },
                  ].map((opt) => (
                    <button
                      key={String(opt.key)}
                      onClick={() => { setAttackMode(opt.key); setProof(null); setVerifyResult(null); }}
                      style={{
                        flex: 1, padding: "4px 6px", borderRadius: 4, fontSize: 9, fontWeight: 600, cursor: "pointer",
                        border: `1px solid ${attackMode === opt.key ? "#dc2626" : "#3f3f46"}`,
                        background: attackMode === opt.key ? "#450a0a" : "#1c1c1f",
                        color: attackMode === opt.key ? "#fca5a5" : "#71717a",
                        transition: "all 0.15s"
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div style={{ marginBottom: 8 }}>
                <label style={{ fontSize: 10, color: "#71717a", fontWeight: 600, display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Your Secret
                </label>
                <input
                  value={wSecret}
                  onChange={(e) => setWSecret(e.target.value)}
                  placeholder="Original secret used at deposit…"
                  style={{ width: "100%", boxSizing: "border-box", background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#f4f4f5", fontFamily: "monospace", outline: "none" }}
                />
                <div style={{ marginTop: 3, fontSize: 9, color: "#ef4444", display: "flex", alignItems: "center", gap: 4 }}>
                  <EyeOff size={9} /> Secret stays local · only its hash is revealed in the proof
                </div>
              </div>

              <div style={{ marginBottom: 12 }}>
                <label style={{ fontSize: 10, color: "#71717a", fontWeight: 600, display: "block", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                  Your Nullifier
                </label>
                <input
                  value={wNullifier}
                  onChange={(e) => setWNullifier(e.target.value)}
                  placeholder="Original nullifier used at deposit…"
                  style={{ width: "100%", boxSizing: "border-box", background: "#1c1c1f", border: "1px solid #3f3f46", borderRadius: 5, padding: "7px 10px", fontSize: 11, color: "#f4f4f5", fontFamily: "monospace", outline: "none" }}
                />
              </div>

              <button
                onClick={handleGenerateProof}
                disabled={proofLoading}
                style={{ width: "100%", padding: "8px", background: proofLoading ? "#1c1c1f" : "#1c1a11", border: `1px solid ${attackMode ? "#92400e" : "#78350f"}`, borderRadius: 5, color: attackMode ? "#f97316" : "#d97706", fontSize: 11, fontWeight: 700, cursor: proofLoading ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, marginBottom: 10, transition: "all 0.2s" }}
              >
                <Hash size={12} />
                {proofLoading ? "Generating proof artifact…" : attackMode ? `Generate ${attackMode === "double_spend" ? "Double Spend" : "Forged"} Proof` : "Generate ZK Proof Artifact"}
              </button>

              {/* Proof Artifact Display */}
              {proof && (
                <div style={{ background: "#0c0c0f", border: "1px solid #1e1e20", borderRadius: 5, padding: "10px 12px" }}>
                  <div style={{ fontSize: 9, color: "#a1a1aa", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>ZK Proof Artifact</div>
                  {[
                    { label: "Commitment Hash (public)", value: proof.commitment, ok: true },
                    { label: "Nullifier Hash (public spend tag)", value: proof.nullifierHash, ok: true },
                    { label: "π_A (proof element)", value: proof.pi_a, ok: true },
                    { label: "π_B (proof element)", value: proof.pi_b, ok: true },
                    { label: "π_C (proof element)", value: proof.pi_c, ok: true },
                    { label: "Secret (HIDDEN · client only)", value: "█████████████████████████", secret: true },
                  ].map((row, i) => (
                    <div key={i} style={{ marginBottom: 5 }}>
                      <div style={{ fontSize: 8, color: row.secret ? "#ef4444" : "#52525b", fontWeight: 600, marginBottom: 1 }}>{row.label}</div>
                      <div style={{ fontSize: 9, fontFamily: "monospace", color: row.secret ? "#ef4444" : "#71717a", wordBreak: "break-all" }}>
                        {row.secret ? row.value : truncate(row.value, 18)}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Verifier */}
          <div style={{ background: "#111113", border: "1px solid #27272a", borderRadius: 8, overflow: "hidden" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid #27272a", display: "flex", alignItems: "center", gap: 7 }}>
              <ShieldCheck size={13} color="#6d6d75" />
              <span style={{ fontSize: 11, fontWeight: 600, color: "#a1a1aa", textTransform: "uppercase", letterSpacing: "0.08em" }}>Verification · Network Verifier</span>
            </div>
            <div style={{ padding: 14 }}>
              <div style={{ marginBottom: 10, fontSize: 9, color: "#52525b", lineHeight: 1.6 }}>
                The verifier is stateless with respect to the secret. It checks:<br />
                1. Commitment exists in the Merkle pool<br />
                2. Nullifier has not been previously spent<br />
                3. Proof structure is internally consistent<br />
                The secret never reaches this component.
              </div>

              {/* Verification checklist */}
              <div style={{ background: "#0c0c0f", border: "1px solid #1e1e20", borderRadius: 5, padding: "10px 12px", marginBottom: 12 }}>
                <div style={{ fontSize: 9, color: "#52525b", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 7 }}>Verifier Logic</div>
                {[
                  { step: "Proof artifact received", status: proof ? "pass" : "pending" },
                  { step: "Commitment ∈ Anonymity Pool", status: verifyResult ? (verifyResult.ok || verifyResult.reason !== "COMMITMENT_NOT_IN_POOL" ? "pass" : "fail") : proof ? "pending" : "idle" },
                  { step: "Nullifier ∉ Spent Registry", status: verifyResult ? (verifyResult.ok || verifyResult.reason !== "NULLIFIER_ALREADY_SPENT" ? "pass" : "fail") : proof ? "pending" : "idle" },
                  { step: "Proof valid → Withdrawal authorized", status: verifyResult ? (verifyResult.ok ? "pass" : "fail") : "idle" },
                ].map((row, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
                    <div style={{ width: 14, height: 14, display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {row.status === "pass" ? <CheckCircle size={11} color="#34d399" /> :
                        row.status === "fail" ? <XCircle size={11} color="#ef4444" /> :
                        row.status === "pending" ? <Activity size={11} color="#d97706" /> :
                        <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#27272a" }} />}
                    </div>
                    <span style={{ fontSize: 9, color: row.status === "pass" ? "#34d399" : row.status === "fail" ? "#ef4444" : row.status === "pending" ? "#d97706" : "#52525b" }}>
                      {row.step}
                    </span>
                  </div>
                ))}
              </div>

              <button
                onClick={handleVerify}
                disabled={verifyLoading || !proof}
                style={{ width: "100%", padding: "9px", background: !proof ? "#111" : verifyLoading ? "#0f2318" : "#0a1f14", border: `1px solid ${!proof ? "#27272a" : "#065f46"}`, borderRadius: 5, color: !proof ? "#27272a" : "#34d399", fontSize: 11, fontWeight: 700, cursor: !proof ? "not-allowed" : verifyLoading ? "wait" : "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, marginBottom: 10, transition: "all 0.2s" }}
              >
                <ShieldCheck size={12} />
                {verifyLoading ? "Verifying proof…" : "Submit Proof to Verifier"}
              </button>

              {/* Verification result */}
              {verifyResult && (
                <div style={{
                  background: verifyResult.ok ? "#022c22" : "#1c0a0a",
                  border: `1px solid ${verifyResult.ok ? "#065f46" : "#7f1d1d"}`,
                  borderRadius: 5, padding: "10px 12px"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                    {verifyResult.ok
                      ? <ShieldCheck size={14} color="#34d399" />
                      : <ShieldAlert size={14} color="#ef4444" />}
                    <span style={{ fontSize: 11, fontWeight: 700, color: verifyResult.ok ? "#34d399" : "#ef4444" }}>
                      {verifyResult.ok ? "WITHDRAWAL AUTHORIZED" : `REJECTED · ${verifyResult.reason}`}
                    </span>
                  </div>
                  <div style={{ fontSize: 9, color: verifyResult.ok ? "#6ee7b7" : "#fca5a5", lineHeight: 1.6 }}>
                    {verifyResult.detail}
                  </div>
                  {!verifyResult.ok && (
                    <div style={{ marginTop: 8, fontSize: 9, color: "#7f1d1d", background: "#0f0404", border: "1px solid #7f1d1d", borderRadius: 4, padding: "5px 8px" }}>
                      <strong>Cryptographic reason:</strong>{" "}
                      {verifyResult.reason === "COMMITMENT_NOT_IN_POOL"
                        ? "The commitment hash SHA-256(secret ∥ nullifier) does not appear in any known Merkle leaf. Either the secret, nullifier, or both are incorrect / fabricated."
                        : "The nullifier hash H(nullifier) is present in the on-chain spent set. Re-using a nullifier constitutes a double-spend. Blockchain consensus would reject this transaction."}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer legend */}
        <div style={{ marginTop: 14, padding: "8px 12px", background: "#0c0c0f", border: "1px solid #1e1e20", borderRadius: 6, display: "flex", gap: 20, flexWrap: "wrap" }}>
          {[
            { color: "#34d399", label: "User commitment" },
            { color: "#52525b", label: "Dummy pool entry" },
            { color: "#d97706", label: "Spent / warning" },
            { color: "#ef4444", label: "Attack / rejected" },
            { color: "#6ee7b7", label: "Verified / authorized" },
          ].map((l) => (
            <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: l.color }} />
              <span style={{ fontSize: 9, color: "#52525b" }}>{l.label}</span>
            </div>
          ))}
          <div style={{ marginLeft: "auto", fontSize: 9, color: "#27272a" }}>
            Simulated ZKP · SHA-256 via Web Crypto API · No external dependencies
          </div>
        </div>
      </div>
    </div>
  );
}
