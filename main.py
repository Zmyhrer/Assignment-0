import random
import re
import math
from collections import Counter
import string
from wordfreq import top_n_list
import urllib.request

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# -----------------------------
# 1. Load wordlist using wordfreq
# -----------------------------
def load_wordlist(top_n=5000):
    common_words = top_n_list('en', top_n)
    common_words_sorted = sorted(common_words, key=len)
    words = set(common_words_sorted)
    print(f"[Setup] Loaded {len(words)} words (top {top_n}) for pattern analysis, sorted by length.")
    return words, common_words_sorted

# -----------------------------
# 2. Preprocess ciphertext
# -----------------------------
def preprocess(ciphertext):
    text = re.sub(r'[^A-Za-z\s]', '', ciphertext).upper()
    print("[Preprocess] Original snippet:", ciphertext[:50])
    print("[Preprocess] Processed snippet:", text[:50])
    return text

# -----------------------------
# 3. Frequency analysis & patterns
# -----------------------------
def frequency_analysis(ciphertext):
    counts = Counter(c for c in ciphertext if c in ALPHA)
    total_letters = sum(counts.values())
    print("[Analysis] Letter frequencies:")
    for c, count in counts.most_common():
        print(f"  {c}: {count} ({count/total_letters:.2%})")
    return counts

def word_pattern(word):
    mapping, next_id = {}, 0
    pattern = []
    for ch in word.upper():
        if ch not in mapping:
            mapping[ch] = chr(ord('A') + next_id)
            next_id += 1
        pattern.append(mapping[ch])
    return "".join(pattern)

def pattern_analysis(ciphertext, common_words, max_candidates=20, min_word_len=3):
    words = re.findall(r"[A-Z]+", ciphertext)
    print("[Analysis] Word patterns (top common words)...")
    for w in words:
        if len(w) >= min_word_len:
            pat = word_pattern(w)
            matches = [wd for wd in common_words if len(wd) == len(w) and word_pattern(wd.upper()) == pat]
            if matches:
                print(f"  {w} ({pat}) -> {matches[:max_candidates]}")
            else:
                print(f"  {w} ({pat}) -> No candidates found")

# -----------------------------
# 4. Candidate key operations
# -----------------------------
def random_key():
    letters = list(ALPHA)
    random.shuffle(letters)
    return {c: p for c, p in zip(ALPHA, letters)}

def swap_key(key, a, b):
    new_key = key.copy()
    new_key[a], new_key[b] = key[b], key[a]
    return new_key

# -----------------------------
# 5. Decode
# -----------------------------
def decode(ciphertext, key):
    return "".join(key.get(c, c) if c in ALPHA else c for c in ciphertext)

# -----------------------------
# 6. Scoring functions
# -----------------------------
def score_plaintext(plaintext, wordlist):
    tokens = re.findall(r"[A-Z]+", plaintext)
    if not tokens:
        return -1e9
    matches = sum(1 for t in tokens if t.lower() in wordlist)
    frac = matches / len(tokens)
    bonus = sum(0.05 for common in ["THE","AND","TO","OF","IN","IS","IT"] if common in plaintext)
    return frac + bonus

# -----------------------------
# 6a. Quadgram scoring from Gutenberg corpus
# -----------------------------
def load_quadgrams_from_gutenberg(book_url="https://www.gutenberg.org/files/1342/1342-0.txt"):
    print(f"[Setup] Downloading book from {book_url} ...")
    try:
        response = urllib.request.urlopen(book_url, timeout=20)
        text = response.read().decode("utf-8").upper()
    except Exception as e:
        print("[Error] Failed to download book:", e)
        return {q: math.log(1e-8) for q in ALPHA}

    text = "".join(c for c in text if c in ALPHA)
    quadgram_counts = Counter(text[i:i+4] for i in range(len(text)-3))
    total = sum(quadgram_counts.values())
    quadgram_logprobs = {q: math.log(c / total) for q, c in quadgram_counts.items()}
    print(f"[Setup] Loaded {len(quadgram_logprobs)} quadgrams from Gutenberg book")
    return quadgram_logprobs

def quadgram_score(text, quadgrams=None):
    if not quadgrams:
        return 0
    score = 0
    for i in range(len(text)-3):
        quad = text[i:i+4]
        if all(c in ALPHA for c in quad):
            score += quadgrams.get(quad, math.log(1e-8))
    return score

def total_score(plaintext, wordlist, quadgrams, w_word=10, w_quad=1):
    return w_word*score_plaintext(plaintext, wordlist) + w_quad*quadgram_score(plaintext, quadgrams)

# -----------------------------
# 7. Simulated annealing / hillclimb
# -----------------------------
def hillclimb(ciphertext, wordlist, quadgrams=None, restarts=20, iterations=10000, init_temp=5.0, cooling=0.990):
    best_score, best_key = -1e9, None
    for r in range(restarts):
        print(f"\n[Search] Restart {r+1}/{restarts}")
        key = random_key()
        plaintext = decode(ciphertext, key)
        score = total_score(plaintext, wordlist, quadgrams)
        temp = init_temp
        for i in range(iterations):
            a, b = random.sample(ALPHA, 2)
            cand_key = swap_key(key, a, b)
            cand_text = decode(ciphertext, cand_key)
            cand_score = total_score(cand_text, wordlist, quadgrams)
            delta = cand_score - score
            if delta > 0 or random.random() < math.exp(delta/temp):
                key, plaintext, score = cand_key, cand_text, cand_score
            temp *= cooling
        if score > best_score:
            best_score, best_key = score, key
            print(f"[Search] New best score: {score:.4f} | Snippet: {plaintext[:100]}")
    return best_key, best_score

# -----------------------------
# 8. Solver entry
# -----------------------------
def run_solver(ciphertext):
    words, common_words = load_wordlist()
    text = preprocess(ciphertext)
    frequency_analysis(text)
    pattern_analysis(text, common_words)
    quadgrams = load_quadgrams_from_gutenberg()
    best_key, best_score = hillclimb(text, words, quadgrams)
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
