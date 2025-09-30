import random
import re
import math
import pickle
import os
from collections import Counter
import string
from wordfreq import top_n_list
import urllib.request
import time

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CACHE_DIR = os.path.expanduser("~/.cache/aristocrat")
os.makedirs(CACHE_DIR, exist_ok=True)

# -----------------------------
# 1. Load wordlist using wordfreq
# -----------------------------
def load_wordlist(top_n=50000):
    common_words = top_n_list('en', top_n)
    common_words_sorted = sorted(common_words, key=len)
    words_set = set(common_words_sorted)
    print(f"[Setup] Loaded {len(words_set)} words (top {top_n}) for pattern analysis, sorted by length.")
    return words_set, common_words_sorted

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
    pattern_map = {}
    for w in words:
        if len(w) >= min_word_len:
            pat = word_pattern(w)
            matches = [wd for wd in common_words if len(wd) == len(w) and word_pattern(wd.upper()) == pat]
            pattern_map[w] = matches[:max_candidates] if matches else []
    return pattern_map

# -----------------------------
# 4. Candidate key operations
# -----------------------------
def random_key(seed_map=None, freq_counts=None):
    letters = list(ALPHA)
    if freq_counts:
        sorted_cipher = [k for k,_ in freq_counts.most_common()]
        sorted_plain = list("ETAOINSHRDLCUMWFGYPBVKJXQZ")
        for i in range(min(len(sorted_cipher), len(sorted_plain))):
            letters[ALPHA.index(sorted_cipher[i])] = sorted_plain[i]
        random.shuffle(letters)  # partial shuffle
    key = {c: p for c, p in zip(ALPHA, letters)}
    if seed_map:
        key.update(seed_map)
    return key

def swap_key(key, a, b):
    new_key = key.copy()
    new_key[a], new_key[b] = key[b], key[a]
    return new_key

# -----------------------------
# 5. Decode
# -----------------------------
def decode(ciphertext, key, preserve_spaces=True):
    if preserve_spaces:
        return "".join(key.get(c, c) if c in ALPHA else c for c in ciphertext)
    else:
        return "".join(key.get(c, c) for c in ciphertext if c in ALPHA)

# -----------------------------
# 6. Scoring functions
# -----------------------------
def score_wordlist(plaintext, wordlist):
    tokens = re.findall(r"[A-Z]+", plaintext)
    if not tokens:
        return -1e9
    matches = sum(1 for t in tokens if t.lower() in wordlist)
    return matches / len(tokens)

def ngram_score(text, ngrams_dict, n=4, smooth=1e-8):
    score = 0
    for i in range(len(text) - n + 1):
        ng = text[i:i+n]
        if all(c in ALPHA for c in ng):
            score += ngrams_dict.get(ng, math.log(smooth))
    return score

def total_score(plaintext, wordlist, quadgrams, bigrams=None, trigrams=None,
                w_word=20, w_quad=5, w_tri=2, w_bi=1):
    word_score = w_word * score_wordlist(plaintext, wordlist)
    quad_score = w_quad * ngram_score(plaintext, quadgrams, 4)/100
    tri_score = w_tri * ngram_score(plaintext, trigrams, 3)/100 if trigrams else 0
    bi_score = w_bi * ngram_score(plaintext, bigrams, 2)/100 if bigrams else 0
    return word_score + quad_score + tri_score + bi_score, word_score, quad_score, tri_score, bi_score

# -----------------------------
# 6a. Load ngrams from Gutenberg
# -----------------------------
def load_ngrams_cached(book_url="https://www.gutenberg.org/files/1342/1342-0.txt"):
    quad_file = os.path.join(CACHE_DIR, "quadgrams.pkl")
    tri_file = os.path.join(CACHE_DIR, "trigrams.pkl")
    bi_file = os.path.join(CACHE_DIR, "bigrams.pkl")

    if os.path.exists(quad_file) and os.path.exists(tri_file) and os.path.exists(bi_file):
        with open(quad_file, "rb") as f: quadgrams = pickle.load(f)
        with open(tri_file, "rb") as f: trigrams = pickle.load(f)
        with open(bi_file, "rb") as f: bigrams = pickle.load(f)
        print(f"[Setup] Loaded ngrams from cache")
        return quadgrams, trigrams, bigrams

    print(f"[Setup] Downloading book from {book_url} ...")
    try:
        response = urllib.request.urlopen(book_url, timeout=20)
        text = response.read().decode("utf-8").upper()
    except Exception as e:
        print("[Error] Failed to download book:", e)
        return {}, {}, {}

    text = "".join(c for c in text if c in ALPHA)
    quadgrams = Counter(text[i:i+4] for i in range(len(text)-3))
    trigrams = Counter(text[i:i+3] for i in range(len(text)-2))
    bigrams = Counter(text[i:i+2] for i in range(len(text)-1))
    total_quad = sum(quadgrams.values())
    total_tri = sum(trigrams.values())
    total_bi = sum(bigrams.values())
    quadgrams = {q: math.log(c/total_quad) for q,c in quadgrams.items()}
    trigrams = {t: math.log(c/total_tri) for t,c in trigrams.items()}
    bigrams = {b: math.log(c/total_bi) for b,c in bigrams.items()}

    with open(quad_file,"wb") as f: pickle.dump(quadgrams,f)
    with open(tri_file,"wb") as f: pickle.dump(trigrams,f)
    with open(bi_file,"wb") as f: pickle.dump(bigrams,f)

    return quadgrams, trigrams, bigrams

# -----------------------------
# 0a. Key Generators
# -----------------------------
def generator_freq(ciphertext):
    freq_counts = frequency_analysis(ciphertext)
    while True:
        yield random_key(freq_counts=freq_counts)

def generator_random(ciphertext):
    while True:
        yield random_key()

def generator_pattern_lock(ciphertext, pattern_map, locked_letters=None):
    locked_letters = locked_letters or {}
    while True:
        yield random_key(seed_map=locked_letters)


# -----------------------------
# 0b. Select best initial key from generators
# -----------------------------
def select_best_start(ciphertext, generators, wordlist, quadgrams, trigrams, bigrams, trials=10):
    best_score, best_key = -1e9, None
    for gen in generators:
        for _ in range(trials):
            key = next(gen)
            plaintext = decode(ciphertext, key)
            score, *_ = total_score(plaintext, wordlist, quadgrams, trigrams, bigrams)
            if score > best_score:
                best_score, best_key = score, key
    return best_key

# -----------------------------
# 7. Hillclimb / simulated annealing
# -----------------------------
def hillclimb(ciphertext, wordlist, quadgrams, trigrams=None, bigrams=None,
              restarts=25, iterations=30000, init_temp=5.0, locked_map=None,
              reference=None):
    best_score, best_key = -1e9, None
    freq_counts = frequency_analysis(ciphertext)
    
    for r in range(restarts):
        start_time = time.time()
        print(f"\n[Search] Restart {r+1}/{restarts}")
        key = random_key(locked_map, freq_counts=freq_counts)
        plaintext = decode(ciphertext, key)
        score, _, _, _, _ = total_score(plaintext, wordlist, quadgrams, trigrams, bigrams)
        temp = init_temp

        top_candidates = []

        for i in range(iterations):
            swap_size = random.choice([2,3,4,5,6,7]) if random.random() < 0.1 else 2
            swaps = random.sample(ALPHA, swap_size)
            cand_key = key.copy()
            for j in range(len(swaps)-1):
                cand_key = swap_key(cand_key, swaps[j], swaps[j+1])
            if random.random() < 0.001:
                cand_key = random_key(freq_counts=freq_counts)

            cand_text = decode(ciphertext, cand_key)
            cand_score, *_ = total_score(cand_text, wordlist, quadgrams, trigrams, bigrams)
            delta = cand_score - score
            if delta > 0 or random.random() < math.exp(delta/temp):
                key, plaintext, score = cand_key, cand_text, cand_score
            temp *= 0.995

            if len(top_candidates) < 5 or score > min(top_candidates)[0]:
                top_candidates.append((score, plaintext))
                top_candidates = sorted(top_candidates, key=lambda x: x[0], reverse=True)[:5]

        elapsed = time.time() - start_time
        if score > best_score:
            best_score, best_key = score, key
            snippet = "\n".join(plaintext[i:i+80] for i in range(0, len(plaintext), 80))
            print(f"[Search] New best score: {score:.4f} | Time: {elapsed:.2f}s | Snippet:\n{snippet[:300]}...")

        if reference:
            letter_acc = sum(d==r for d,r in zip(plaintext, reference.upper()) if d in ALPHA and r in ALPHA)/max(len(reference),1)
            ref_words = re.findall(r"[A-Z]+", reference.upper())
            decoded_words = re.findall(r"[A-Z]+", plaintext)
            word_acc = sum(d==r for d,r in zip(decoded_words, ref_words))/max(len(ref_words),1)
            print(f"[Diagnostics] Letter-level accuracy: {letter_acc:.2%}, Word-level accuracy: {word_acc:.2%}")

        print("[Top candidates snippet]:")
        for s, p in top_candidates:
            print(p[:100], "... Score:", s)

    return best_key, best_score

# -----------------------------
# 8. Solver entry
# -----------------------------
def run_solver(ciphertext, reference=None):
    words_set, common_words = load_wordlist()
    text = preprocess(ciphertext)
    pattern_map = pattern_analysis(text, common_words)
    quadgrams, trigrams, bigrams = load_ngrams_cached()

    generators = [
        generator_freq(text),
        generator_random(text),
        generator_pattern_lock(text, pattern_map)
    ]

    best_start_key = select_best_start(text, generators, words_set, quadgrams, trigrams, bigrams, trials=10)
    
    best_key, best_score = hillclimb(
        text,
        words_set,
        quadgrams,
        trigrams,
        bigrams,
        locked_map=best_start_key,
        reference=reference
    )

    if best_key:
        plaintext = decode(text, best_key)
        print("\n[Result] Best score:", best_score)
        print("[Result] Plaintext candidate:\n")
        for i in range(0, len(plaintext), 80):
            print(plaintext[i:i+80])

# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    cipher_example = """YPLOBGT TOH OSOHHDO PF RHP VDOOS RDPLH RHP LPE DPDDLY SPLRHBG. QDWD DODG RO RHP QMQOLR OROHHR KOYDO, RDQ DOLWBDOB RBP RDPM RDHLVDO RHDL. M ZSD YSOHR PF M RDDA, XPHDOODG RHVR M DMPLOR MPD. RPLRHDO SHBRRWDH HTRRDOH SLHP, RDQ RDPLRDOO GLODOP TLYRDO PF JRSWDOH."""
    
    run_solver(cipher_example)
