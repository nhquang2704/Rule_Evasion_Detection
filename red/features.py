"""Feature extraction using TF-IDF or Count vectorization.

Normalized samples are comma-separated token strings. The vectorizer
uses a comma-split tokenizer to convert them into TF-IDF feature vectors.

Usage
-----
    vectorizer = create_vectorizer("tfidf")
    X_train = vectorizer.fit_transform(train_samples_iter)
    X_valid = vectorizer.transform(valid_samples_iter)
"""

from sklearn.feature_extraction.text import (
    TfidfVectorizer,
    CountVectorizer,
    HashingVectorizer,
)
from sklearn.preprocessing import MaxAbsScaler
from sklearn.pipeline import Pipeline


def comma_tokenizer(text: str) -> list:
    """Split normalized sample on commas."""
    return text.split(",")


def create_vectorizer(method: str = "tfidf", ngram_range=(1, 1), analyzer="word"):
    """Create a sklearn text vectorizer.

    Parameters
    ----------
    method : str
        One of: "tfidf", "count", "binary_count", "hashing", "scaled_count".
    ngram_range : tuple
        N-gram range for the vectorizer, e.g. (1, 1) for unigrams.
    analyzer : str
        "word" or "char".

    Returns
    -------
    sklearn estimator
        A fitted-ready vectorizer (call .fit_transform / .transform).
    """
    if method == "tfidf":
        return TfidfVectorizer(
            tokenizer=comma_tokenizer,
            analyzer=analyzer,
            ngram_range=ngram_range,
        )
    elif method == "count":
        return CountVectorizer(
            tokenizer=comma_tokenizer,
            analyzer=analyzer,
            ngram_range=ngram_range,
        )
    elif method == "binary_count":
        return CountVectorizer(
            tokenizer=comma_tokenizer,
            analyzer=analyzer,
            ngram_range=ngram_range,
            binary=True,
        )
    elif method == "hashing":
        return HashingVectorizer(
            tokenizer=comma_tokenizer,
            analyzer=analyzer,
            ngram_range=ngram_range,
        )
    elif method == "scaled_count":
        return Pipeline(
            steps=[
                (
                    "count",
                    CountVectorizer(
                        tokenizer=comma_tokenizer,
                        analyzer=analyzer,
                        ngram_range=ngram_range,
                    ),
                ),
                ("scaling", MaxAbsScaler()),
            ]
        )
    else:
        raise ValueError(f"Unknown vectorization method: {method}")
