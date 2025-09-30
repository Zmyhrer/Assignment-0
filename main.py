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
        return words
    except Exception as e:
        print("[Warning] Wordlist download failed, fallback to small set:", e)
        return {"the", "and", "to", "of", "in", "is", "it", "be", "as", "at", "on"}

# -----------------------------
# 2. Preprocess
# -----------------------------

def preprocess(ciphertext):
    text = ciphertext.upper()
    print("[Preprocess] Ciphertext length:", len(text))
    return text

# -----------------------------
# 3. Initial analysis
# -----------------------------

def frequency_analysis(ciphertext):
    counts = Counter(c for c in ciphertext if c in ALPHA)
    print("[Analysis] Frequency counts:", counts.most_common())
    return counts

def word_pattern(word):
    """Generate pattern like ABA for word XYX."""
    mapping = {}
    next_id = 0
    pattern = []
    for ch in word:
        if ch not in mapping:
            mapping[ch] = chr(ord('A') + next_id)
            next_id += 1
        pattern.append(mapping[ch])
    return "".join(pattern)

def pattern_analysis(ciphertext, wordlist):
    words = re.findall(r"[A-Z]+", ciphertext)
    print("[Analysis] Word patterns...")
    for w in words:
        if len(w) > 2:  # focus on 3+ letter words
            pat = word_pattern(w)
            matches = [wd for wd in wordlist if len(wd) == len(w) and word_pattern(wd.upper()) == pat]
            if len(matches) < 10 and matches:
                print(f"  Cipherword {w} pattern {pat} -> candidates {matches[:5]}")

# -----------------------------
# 4. Candidate key representation
# -----------------------------

def random_key():
    letters = list(ALPHA)
    perm = letters[:]
    random.shuffle(perm)
    return {c: p for c, p in zip(letters, perm)}

def swap_key(key, a, b):
    new_key = key.copy()
    new_key[a], new_key[b] = key[b], key[a]
    return new_key

# -----------------------------
# 5. Decoding function
# -----------------------------

def decode(ciphertext, key):
    return "".join(key.get(c, c) if c in ALPHA else c for c in ciphertext)

# -----------------------------
# 6. Scoring function
# -----------------------------

def score_plaintext(plaintext, wordlist):
    tokens = re.findall(r"[A-Z]+", plaintext)
    if not tokens:
        return -1e9
    matches = sum(1 for t in tokens if t.lower() in wordlist)
    frac = matches / len(tokens)
    bonus = 0
    for common in ["THE", "AND", "TO", "OF", "IN", "IS", "IT"]:
        if common in plaintext:
            bonus += 0.05
    return frac + bonus

# -----------------------------
# 7. Search strategy
# -----------------------------

def hillclimb(ciphertext, wordlist, restarts=5, iterations=1000, log_interval=200):
    best_score, best_key = -1e9, None
    for r in range(restarts):
        print(f"\n[Search] Restart {r+1}/{restarts}")
        key = random_key()
        plaintext = decode(ciphertext, key)
        score = score_plaintext(plaintext, wordlist)
        print("[Search] Initial score:", score)
        print("[Search] Initial snippet:", plaintext[:60])
        for i in range(iterations):
            a, b = random.sample(ALPHA, 2)
            cand_key = swap_key(key, a, b)
            cand_text = decode(ciphertext, cand_key)
            cand_score = score_plaintext(cand_text, wordlist)
            if cand_score > score:
                key, score, plaintext = cand_key, cand_score, cand_text
                if i % log_interval == 0:
                    print(f"  Iter {i} | Improved score: {score:.4f} | Snippet: {plaintext[:60]}")
        if score > best_score:
            best_score, best_key = score, key
            print("[Search] New best score:", score)
            print("[Search] Candidate plaintext:", plaintext[:100])
    return best_key, best_score

# -----------------------------
# 8. Refinement & stop criteria
# -----------------------------

def run_solver(ciphertext):
    words = load_wordlist()
    text = preprocess(ciphertext)
    frequency_analysis(text)
    pattern_analysis(text, words)
    best_key, best_score = hillclimb(text, words, restarts=3, iterations=1000)
    if best_key:
        plaintext = decode(text, best_key)
        print("\n[Result] Best score:", best_score)
        print("[Result] Plaintext candidate:\n", plaintext)

# -----------------------------
# Example usage
# -----------------------------

if __name__ == "__main__":
    cipher_example = "ERR EERRRE RR ERR RERR ERERRERE ERERR ERR EERE ERE..."
    run_solver(cipher_example)
