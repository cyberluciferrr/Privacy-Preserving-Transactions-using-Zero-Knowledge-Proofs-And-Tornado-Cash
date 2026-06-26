# Privacy Preserving Transactions with ZKP (Tornado Cash Simulation)

A sleek, tactile, single page React application demonstrating the core cryptographic principles of **Zero Knowledge Proofs (ZKP)** and **Anonymity Mixing Pools** modeled after Tornado Cash architecture. Built for a 5th semester Blockchain Assignment.

---

## Key Features & Architecture

*   **Commitment Phase (Deposit):** Generates a random cryptographic secret combined with a user defined **Nullifier** to construct a deterministic SHA 256 hash commitment deposited directly into the visual ledger pool.
*   **The Mixing Pool (Anonymity Set):** Blends user transactions natively with pre seeded structural commitments, breaking direct public ledger linkability.
*   **Proof Phase (ZKP Simulation):** Demonstrates membership proof generation. Prove knowledge of an active unspent deposit commitment without exposing the underlying private secret key.
*   **Verification & Prevention Layer:** Implements strict cryptographic network verification logic. Tracks a ledger of spent nullifiers to provide programmatic **Double Spending Prevention** and active malicious/forged proof rejection.
*   **Interactive MiniMerkle Tree:** Visually traces tree updates, mapping leaf insertions down to dynamic Merkle Root recalculation.

---

## Tech Stack & UI Philosophy

*   **Core Framework:** React 19 + Vite
*   **Design System:** Tailwind CSS (Tactile High Contrast Enterprise Dark Theme)
*   **Iconset:** Lucide React
*   **Philosophy:** Anti generic AI styling. Employs crisp border definitions, tight context-aware component clusters, zero structural layout waste, and responsive state micro interactions.

---

## Quick Start Guide

### Prerequisites
Ensure you have [Node.js](https://nodejs.org/) installed on your local machine.

### Installation & Launch
1. Clone the repository and navigate to the project root:
   ```bash
   git clone <your-repository-url>
   cd tornado-demo
   ```
2. Install the necessary development and design assets:
   ```bash
   npm install
   npm install -D tailwindcss postcss autoprefixer
   npm install lucide-react
   ```
3. Run the local development server:
   ```bash
   npm run dev
   ```
4. Open [http://localhost:5173](http://localhost:5173) in your browser to interact with the application. (whatever the localhost url you will get)
