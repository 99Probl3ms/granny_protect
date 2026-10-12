// Combine independent signal weights: each weight is read as "probability
// this signal alone means phishing", so 1 - Π(1 - w). Never exceeds 1 and
// stacking weak signals rises slowly.
export function noisyOr(weights) {
  let keep = 1;
  for (const w of weights) keep *= 1 - Math.min(Math.max(w, 0), 1);
  return Math.round((1 - keep) * 1000) / 1000;
}
