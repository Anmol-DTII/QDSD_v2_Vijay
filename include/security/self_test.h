/**
 * @file self_test.h
 * @brief Power-on known-answer tests (SHA-256, P-256 verify, RNG).
 */
#ifndef QDSD_SELFTEST_H
#define QDSD_SELFTEST_H

/** 0 = pass, negative = which check failed. */
int qdsd_crypto_selftest(void);

#endif /* QDSD_SELFTEST_H */
