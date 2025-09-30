import random
import re
import math
from collections import Counter
import urllib.request
import os

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# -----------------------------
# 1. Collect inputs & resources
# -----------------------------
def load_wordlist(local_path="words_alpha.txt", url=None):
    """Load or download English word list for scoring."""
    if os.path.exists(local_path):
        with open(local_path, "r", encoding="utf-8") as f:
            return {w.strip().lower() for w in f if w.strip()}
    if url is None:
        url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
    try:
        print("[Setup] Downloading wordlist...")
        r = urllib.request.urlopen(url, timeout=20)
        text = r.read().decode("utf-8")
        words = {w.strip().lower() for w in text.splitlines() if w.strip()}
        print(f"[Setup] Loaded wordlist: {len(words)} words. Sample: {list(words)[:10]}")
        return words
    except Exception as e:
        print("[Warning] Wordlist download failed, using fallback:", e)
        return {"the", "and", "to", "of", "in", "is", "it", "be", "as", "at", "on"}

# -----------------------------
# 2. Preprocess
# -----------------------------
def preprocess(ciphertext):
    text = ciphertext.upper()
    print("[Preprocess] Original snippet:", ciphertext[:50])
    print("[Preprocess] Processed snippet:", text[:50])
    return text


# -----------------------------
# 3. Initial analysis
# -----------------------------
def frequency_analysis(ciphertext):
    counts = Counter(c for c in ciphertext if c in ALPHA)
    total_letters = sum(counts.values())
    freqs = [(c, count, count/total_letters) for c, count in counts.most_common()]
    print("[Analysis] Letter frequencies (letter, count, fraction):")
    for c, count, frac in freqs:
        print(f"  {c}: {count} ({frac:.2%})")
    return counts


def word_pattern(word):
    """Generate letter pattern e.g., ABA for XYX."""
    mapping, next_id = {}, 0
    pattern = []
    for ch in word:
        if ch not in mapping:
            mapping[ch] = chr(ord('A') + next_id)
            next_id += 1
        pattern.append(mapping[ch])
    return "".join(pattern)

def pattern_analysis(ciphertext, wordlist, max_candidates=5):
    words = re.findall(r"[A-Z]+", ciphertext)
    print("[Analysis] Word patterns...")
    for w in words:
        if len(w) > 2:
            pat = word_pattern(w)
            matches = [wd for wd in wordlist if len(wd) == len(w) and word_pattern(wd.upper()) == pat]
            if matches:
                print(f"  {w} ({pat}) -> {matches[:max_candidates]}")
            else:
                print(f"  {w} ({pat}) -> No candidates found")


# -----------------------------
# 4. Candidate key representation
# -----------------------------
def random_key():
    letters = list(ALPHA)
    perm = letters[:]
    random.shuffle(perm)
    key = {c: p for c, p in zip(letters, perm)}
    return key

def swap_key(key, a, b):
    new_key = key.copy()
    new_key[a], new_key[b] = key[b], key[a]
    return new_key


# -----------------------------
# 5. Decoding function
# -----------------------------
def decode(ciphertext, key):
    decoded = "".join(key.get(c, c) if c in ALPHA else c for c in ciphertext)
    return decoded


# -----------------------------
# 6. Scoring function
# -----------------------------
def score_plaintext(plaintext, wordlist):
    tokens = re.findall(r"[A-Z]+", plaintext)
    if not tokens:
        return -1e9
    matches = sum(1 for t in tokens if t.lower() in wordlist)
    frac = matches / len(tokens)
    bonus = sum(0.05 for common in ["THE","AND","TO","OF","IN","IS","IT"] if common in plaintext)
    total_score = frac + bonus
    return total_score


# Optional: Quadgram scoring
def load_quadgrams(url=None):
    """
    Load quadgram frequencies and convert to log probabilities.
    Falls back to uniform probabilities if download fails.
    """
    quadgram_counts = {}
    if url is None:
        # Use a more realistic source for quadgrams if possible
        url = "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"  # placeholder
    
    try:
        print("[Setup] Downloading quadgrams...")
        r = urllib.request.urlopen(url, timeout=20)
        text = r.read().decode("utf-8")
        total_quads = 0
        for word in text.splitlines():
            word = word.strip().upper()
            for i in range(len(word)-3):
                q = word[i:i+4]
                if all(c in ALPHA for c in q):
                    quadgram_counts[q] = quadgram_counts.get(q, 0) + 1
                    total_quads += 1
        
        # Convert counts to log probabilities
        quadgram_logprobs = {}
        for q, count in quadgram_counts.items():
            prob = count / total_quads
            quadgram_logprobs[q] = math.log(prob)
        
        print(f"[Setup] Loaded {len(quadgram_logprobs)} quadgrams. Sample: {list(quadgram_logprobs.items())[:5]}")
        return quadgram_logprobs
    except Exception as e:
        print("[Warning] Quadgram download failed:", e)
        # Return uniform small log probability for unknown quads
        uniform_prob = math.log(0.01)
        return {q: uniform_prob for q in ALPHA}

def quadgram_score(text, quadgrams=None):
    """
    Compute quadgram log probability score.
    Uses log probabilities to avoid extremely low values dominating the score.
    """
    if not quadgrams:
        return 0
    
    score = 0
    for i in range(len(text) - 3):
        quad = text[i:i+4]
        if all(c in ALPHA for c in quad):
            # Use a small default log-probability for unseen quadgrams
            score += quadgrams.get(quad, math.log(0.01))
    
    return score


# -----------------------------
# 7. Search strategy (hillclimb + annealing)
# -----------------------------
def hillclimb(ciphertext, wordlist, quadgrams=None, restarts=5, iterations=1000, log_interval=200, temp=0.05):
    best_score, best_key = -1e9, None
    for r in range(restarts):
        print(f"\n[Search] Restart {r+1}/{restarts}")
        key = random_key()
        plaintext = decode(ciphertext, key)
        score = score_plaintext(plaintext, wordlist) + quadgram_score(plaintext, quadgrams)
        print(f"[Search] Initial score: {score:.4f} | Snippet: {plaintext[:60]}")
        
        for i in range(iterations):
            a, b = random.sample(ALPHA, 2)
            cand_key = swap_key(key, a, b)
            cand_text = decode(ciphertext, cand_key)
            cand_score = score_plaintext(cand_text, wordlist) + quadgram_score(cand_text, quadgrams)
            
            accepted = False
            if cand_score > score or random.random() < math.exp((cand_score - score)/temp):
                key, plaintext, score = cand_key, cand_text, cand_score
                accepted = True
                if i % log_interval == 0 or cand_score > score:
                    print(f"  Iter {i}: Swap {a}<->{b} accepted | Score: {score:.4f} | Snippet: {plaintext[:60]}")
            else:
                if i % log_interval == 0:
                    print(f"  Iter {i}: Swap {a}<->{b} rejected | Score remains: {score:.4f}")
        
        if score > best_score:
            best_score, best_key = score, key
            print(f"[Search] New best score: {score:.4f} | Snippet: {plaintext[:100]}")
    return best_key, best_score


# -----------------------------
# 8. Refinement & result
# -----------------------------
def run_solver(ciphertext):
    words = load_wordlist()
    text = preprocess(ciphertext)
    frequency_analysis(text)
    pattern_analysis(text, words)
    
    # Optional: load quadgrams
    quadgrams = load_quadgrams()
    
    best_key, best_score = hillclimb(text, words, quadgrams, restarts=3, iterations=1000)
    
    if best_key:
        plaintext = decode(text, best_key)
        print("\n[Result] Best score:", best_score)
        print("[Result] Plaintext candidate:\n", plaintext)

# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    cipher_example = """ZIT LZGFTL GF ZIT IOSS VIOLHTKTR VIOST ZIT VOFR VQL EGXFZOFU RQNL. OF ZIT DQKATZ ZIT WQATK IXDDTR QF GSR ZXFT QFR EIOSRKTF EIQLTR ZIT AOZT QSGFU ZIT SQFT. TCTFOFU YTSS QFR SQFZTKFL WSOFATR SOAT YOKTYSOTL; LZKQFUTKL LIQKTR LZGKOTL XFRTK ZIT TSD. Q LDQSS ESGEA LZKXEA DORFOUIZ QL ROLZQFZ WTSSL KTHSOTR."""
    run_solver(cipher_example)
