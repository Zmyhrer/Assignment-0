import random
import string
import time
import math
import requests
import io
import os
from collections import Counter
from typing import Dict, List, Tuple, Set, Optional
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
QUADGRAM_URL = "https://raw.githubusercontent.com/jameslyons/python_cryptanalysis/master/quadgrams.txt"
LOCAL_QUADGRAM_FILE = "english_quadgrams.txt"  # fallback if remote fails

# --- Ciphertext (example) ---
CIPHERTEXT = (
    "ZIT LZGFTL GF ZIT HIQQ ZHIKYERED ZHIQE ZIT ZIND ZAK LUXNTING DAWK. IN THE BARJET "
    "THE OAJER HXBBED AN UQD TXNE AND LHIQDREN LHAKED THE JITE AQUNG THE "
    "QANE. EPENING MEQQ AND QANTERNK OQIJED QIJE MIREMQIEK; KTRANGERK KHARED KTURIEK "
    "XNDER THE EQB. A KBAQQ LQULJ KTRXLJ BIDHIGHT AK \"DIKTANT OEQQK REYQIED.\""
)

ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ALPHABET = list(string.ascii_uppercase)


def load_quadgrams(url: str = QUADGRAM_URL, local_path: str = LOCAL_QUADGRAM_FILE) -> Dict[str, float]:
    """Load quadgram frequencies (remote if possible, fallback to local)."""
    text_data = None
    try:
        print(f"Fetching quadgram data from: {url}")
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        text_data = response.text
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(text_data)
    except Exception:
        if os.path.exists(local_path):
            print(f"⚠️ Remote fetch failed, using cached file: {local_path}")
            with open(local_path, "r", encoding="utf-8") as f:
                text_data = f.read()
        else:
            raise RuntimeError("Failed to fetch quadgrams and no local fallback available.")

    quad_counts: Dict[str, int] = {}
    total_quadgrams = 0
    for line in io.StringIO(text_data.upper()):
        try:
            quad, count_str = line.split()
            if len(quad) == 4 and quad.isalpha() and count_str.isdigit():
                count = int(count_str)
                quad_counts[quad] = count
                total_quadgrams += count
        except ValueError:
            continue

    if total_quadgrams == 0:
        raise RuntimeError("Quadgram file was empty or corrupted.")

    # Convert counts to log probabilities
    return {quad: math.log10(count / total_quadgrams) for quad, count in quad_counts.items()}


class NgramScore:
    """Calculate log probability of text using quadgrams."""
    def __init__(self, quadgram_data: Dict[str, float]):
        self.quad_scores = quadgram_data
        self.floor_log_prob = -15.0
        self.valid_chars = set(ALPHABET) | {" "}

    def _get_ngrams(self, text: str, n: int) -> List[str]:
        normalized = "".join(c for c in text.upper() if c in self.valid_chars)
        return [normalized[i:i+n] for i in range(len(normalized)-n+1)] if len(normalized) >= n else []

    def get_fitness(self, text: str) -> float:
        return sum(self.quad_scores.get(q, self.floor_log_prob) for q in self._get_ngrams(text, 4))


class GeneticSolver:
    """Genetic algorithm for solving substitution ciphers."""
    def __init__(self, ciphertext: str, population_size: int = 200, quadgram_data: Dict[str, float] = None):
        self.raw_ciphertext = ciphertext
        self.ciphertext_letters_only = "".join(c for c in ciphertext.upper() if c in ALPHABET)
        if quadgram_data is None:
            raise ValueError("quadgram_data must be provided.")
        self.scorer = NgramScore(quadgram_data)
        self.population_size = population_size
        self.alphabet = ALPHABET
        self.population: List[Dict[str, str]] = []
        self.cipher_freq_order: List[str] = self._get_frequency_order()

    def _get_frequency_order(self) -> List[str]:
        counts = Counter(self.ciphertext_letters_only)
        return [item[0] for item, _ in sorted(counts.items(), key=lambda x: x[1], reverse=True)]

    def _create_random_key(self) -> Dict[str, str]:
        plain = self.alphabet[:]
        random.shuffle(plain)
        return dict(zip(self.alphabet, plain))

    def _create_smart_key(self) -> Dict[str, str]:
        key: Dict[str, str] = {}
        used_plain: Set[str] = set()
        for i, cipher_char in enumerate(self.cipher_freq_order):
            if i < len(ENGLISH_FREQ_ORDER):
                key[cipher_char] = ENGLISH_FREQ_ORDER[i]
                used_plain.add(ENGLISH_FREQ_ORDER[i])
        remaining_cipher = [c for c in self.alphabet if c not in key]
        remaining_plain = [p for p in self.alphabet if p not in used_plain]
        random.shuffle(remaining_plain)
        key.update(dict(zip(remaining_cipher, remaining_plain)))
        return key

    def initialize_population(self):
        self.population = [self._create_smart_key()] + [self._create_random_key() for _ in range(self.population_size-1)]

    def _decrypt(self, key: Dict[str, str]) -> str:
        return "".join(key.get(c, c) if c in ALPHABET else c for c in self.raw_ciphertext.upper())

    def get_fitness_scores(self) -> List[Tuple[Dict[str, str], float]]:
        """Parallel fitness evaluation for faster performance."""
        results: List[Tuple[Dict[str, str], float]] = []
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.scorer.get_fitness, self._decrypt(k)) for k in self.population]
            results = list(zip(self.population, [f.result() for f in futures]))
        return results

    def selection_tournament(self, scored_population: List[Tuple[Dict[str, str], float]],
                             elite_count: int, tournament_size: int = 5) -> List[Dict[str, str]]:
        scored_population.sort(key=lambda x: x[1], reverse=True)
        next_gen = [key for key, _ in scored_population[:elite_count]]
        while len(next_gen) < self.population_size:
            competitors = random.sample(scored_population, min(tournament_size, len(scored_population)))
            winner_key, _ = max(competitors, key=lambda x: x[1])
            next_gen.append(winner_key)
        return next_gen

    def ordered_crossover(self, parent1: Dict[str, str], parent2: Dict[str, str]) -> Dict[str, str]:
        p1_list = [parent1[c] for c in self.alphabet]
        p2_list = [parent2[c] for c in self.alphabet]
        size = len(self.alphabet)
        c1, c2 = sorted(random.sample(range(size), 2))
        child_list = [''] * size
        child_list[c1:c2+1] = p1_list[c1:c2+1]
        used = set(child_list[c1:c2+1])
        p2_order = [p for p in p2_list if p not in used]
        idx = 0
        for i in range(size):
            if i < c1 or i > c2:
                child_list[i] = p2_order[idx]
                idx += 1
        return dict(zip(self.alphabet, child_list))

    def mutate(self, key: Dict[str, str], mutation_rate: float) -> Dict[str, str]:
        key_copy = key.copy()
        if random.random() < mutation_rate:
            c1, c2 = random.sample(self.alphabet, 2)
            key_copy[c1], key_copy[c2] = key_copy[c2], key_copy[c1]
        return key_copy

    def solve(self, generations: int = 5000, elite_percent: float = 0.05,
              base_mutation_rate: float = 0.05, stagnation_limit: int = 200,
              tournament_size: int = 5):
        start_time = time.time()
        self.initialize_population()
        elite_count = max(1, int(self.population_size * elite_percent))
        best_key_global: Optional[Dict[str, str]] = None
        best_score_global = -float('inf')
        generations_stagnant = 0
        current_mutation_rate = base_mutation_rate

        print(f"--- Starting Genetic Algorithm Solver ({self.population_size} keys, {generations} generations) ---")

        for generation in range(1, generations+1):
            scored_population = self.get_fitness_scores()
            current_best_key, current_best_score = max(scored_population, key=lambda x: x[1])

            if current_best_score > best_score_global:
                best_score_global = current_best_score
                best_key_global = current_best_key.copy()
                generations_stagnant = 0
                current_mutation_rate = base_mutation_rate
            else:
                generations_stagnant += 1
                if generations_stagnant >= stagnation_limit:
                    current_mutation_rate = min(0.8, current_mutation_rate + 0.1)
                    generations_stagnant = 0

            if generation % max(1, generations // 10) == 0:
                print(f"Gen {generation}/{generations} | Best Score: {best_score_global:.2f} | "
                      f"Current Gen Best: {current_best_score:.2f} | Mut Rate: {current_mutation_rate:.2f}")

            parents = self.selection_tournament(scored_population, elite_count, tournament_size)
            new_population = parents[:elite_count]
            while len(new_population) < self.population_size:
                p1, p2 = random.sample(parents, 2)
                child = self.ordered_crossover(p1, p2)
                child = self.mutate(child, current_mutation_rate)
                new_population.append(child)
            self.population = new_population

        end_time = time.time()
        final_key = best_key_global or current_best_key
        plaintext = self._decrypt(final_key)
        print("-" * 70)
        print("GENETIC ALGORITHM COMPLETE")
        print(f"Total Time: {end_time - start_time:.2f}s")
        print(f"Global Best Score Found: {best_score_global:.2f}")

        print("\nBEST KEY (cipher -> plain):")
        key_list = sorted(final_key.items())
        print(" ".join(f"{c}->{p}" for c, p in key_list))

        print("\nDECODED PLAINTEXT (Best Guess):")
        for i in range(0, len(plaintext), 80):
            print(plaintext[i:i+80])


if __name__ == "__main__":
    quadgram_data = load_quadgrams()
    random.seed(42)  # deterministic for testing
    solver = GeneticSolver(CIPHERTEXT, population_size=500, quadgram_data=quadgram_data)
    solver.solve(generations=5000, elite_percent=0.05, base_mutation_rate=0.05, stagnation_limit=200, tournament_size=4)
