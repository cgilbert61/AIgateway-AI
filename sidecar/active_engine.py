import numpy as np
import time

# Layer 2 State Space Constants
STATE_SAFE_INTENT = 0
STATE_NEUTRAL_INTENT = 1
STATE_EXFIL_INTENT = 2

# Layer 2 Actions (Priors to set for Layer 1)
ACTION_SET_PRIOR_SAFE = 0
ACTION_SET_PRIOR_NEUTRAL = 1
ACTION_SET_PRIOR_EXFIL = 2

class Layer2Engine:
    def __init__(self, raw_a2, raw_b2, raw_c2):
        # Column normalize A2
        self.A2 = np.array(raw_a2, dtype=float)
        self.A2 = self.A2 / (self.A2.sum(axis=0) + 1e-16)

        # Column normalize B2 for each action: [state_next][state_prev][action]
        self.B2 = np.array(raw_b2, dtype=float)
        for act in range(self.B2.shape[2]):
            col_sums = self.B2[:, :, act].sum(axis=0)
            self.B2[:, :, act] = self.B2[:, :, act] / (col_sums + 1e-16)

        self.C2 = np.array(raw_c2, dtype=float)
        self.prior_beliefs = np.array([0.90, 0.08, 0.02])
        self.history_beliefs = [self.prior_beliefs.copy()]
        self.history_actions = []
        self.ticks = 0
        self.last_request_time = time.time()

    def update_perception(self, prev_action, observation):
        """
        Runs Layer 2 perception update (Bayesian state update over intents)
        """
        # Apply time-based decay of beliefs toward homeostatic resting state
        now = time.time()
        elapsed = now - self.last_request_time
        self.last_request_time = now
        
        homeostatic_state = np.array([0.90, 0.08, 0.02])
        decay_lambda = 1.0 - np.exp(-elapsed * 0.01)
        self.prior_beliefs = (1.0 - decay_lambda) * self.prior_beliefs + decay_lambda * homeostatic_state

        # 1. Prior state prediction
        if prev_action is None:
            prior_qs = self.prior_beliefs.copy()
        else:
            prior_qs = self.B2[:, :, prev_action] @ self.prior_beliefs

        # 2. Bayesian update with observation
        unnormalized = self.A2[observation, :] * prior_qs
        sum_un = unnormalized.sum()
        if sum_un > 0:
            qs = unnormalized / sum_un
        else:
            qs = prior_qs.copy()

        # 3. Compute Variational Free Energy (VFE)
        kl = 0.0
        for i in range(3):
            if qs[i] > 0:
                p_val = prior_qs[i] if prior_qs[i] > 0 else 1e-16
                a_val = self.A2[observation, i] if self.A2[observation, i] > 0 else 1e-16
                kl += qs[i] * (np.log(qs[i]) - np.log(p_val)) - qs[i] * np.log(a_val)
        
        self.prior_beliefs = qs
        self.history_beliefs.append(qs.copy())
        self.ticks += 1
        return qs, kl

    def select_action(self, qs, gamma=3.0):
        """
        Runs Layer 2 action selection based on Expected Free Energy (EFE)
        """
        # Habit bias E
        E = np.array([0.95, 0.04, 0.01])
        efe = np.zeros(3)

        for action in range(3):
            # Predict next state
            qs_pred = self.B2[:, :, action] @ qs
            # Predict next observation
            qo_pred = self.A2 @ qs_pred

            # Expected Free Energy: G = sum_s qs_pred[s] * sum_o A[o][s] * (ln(A[o][s]) - C[o])
            g = 0.0
            for s_idx in range(3):
                for o_idx in range(3):
                    val_a = self.A2[o_idx, s_idx]
                    log_a = np.log(val_a) if val_a > 0 else 0.0
                    g += qs_pred[s_idx] * val_a * (log_a - self.C2[o_idx])
            efe[action] = g

        # Softmax selection: ln(E[a]) - gamma * G(a)
        log_q_pi = np.log(E) - gamma * efe
        log_q_pi_max = np.max(log_q_pi)
        q_pi = np.exp(log_q_pi - log_q_pi_max)
        q_pi = q_pi / q_pi.sum()

        decided_action = int(np.argmax(q_pi))
        self.history_actions.append(decided_action)
        return decided_action, q_pi

    def adjust_layer1_matrices(self, decided_action, default_a1, default_b1):
        """
        Generates top-down contextual priors for Layer 1.
        Modifies transition probabilities default_b1 and likelihoods default_a1 based on intent.
        """
        a1 = np.array(default_a1, dtype=float)
        b1 = np.array(default_b1, dtype=float)

        if decided_action == ACTION_SET_PRIOR_SAFE:
            # Safe intent: use baseline parameters
            pass
        elif decided_action == ACTION_SET_PRIOR_NEUTRAL:
            # Neutral intent: increase suspicious/malicious likelihood sensitivity in A1,
            # and transition probabilities to Suspicious state.
            a1[1, 0] = 0.2  # Make Safe state produce more StructureShifts
            a1[3, 0] = 0.1  # Make Safe state produce more IngressFloods
            # Shift transition from Safe to Suspicious under ALLOW action
            b1[1, 0, 0] = 0.4
            b1[0, 0, 0] = 0.59
        elif decided_action == ACTION_SET_PRIOR_EXFIL:
            # Exfiltrating/Anomalous intent: Extreme restriction.
            # Make any non-read observation map strongly to Malicious state (A1).
            # Force transitions to Malicious state under ALLOW/MONITOR actions.
            a1[1, :] = [0.01, 0.1, 0.89] # StructureShift -> Malicious
            a1[3, :] = [0.01, 0.1, 0.89] # IngressFlood -> Malicious
            # High probability of transitioning to Malicious (2) from any state
            b1[2, 0, 0] = 0.8
            b1[2, 1, 0] = 0.9
            b1[0, 0, 0] = 0.19
            b1[1, 1, 0] = 0.09

        # Re-normalize columns to maintain valid probabilities
        # A1 normalization
        a1 = a1 / (a1.sum(axis=0) + 1e-16)
        # B1 normalization
        for act in range(b1.shape[2]):
            col_sums = b1[:, :, act].sum(axis=0)
            b1[:, :, act] = b1[:, :, act] / (col_sums + 1e-16)

        return a1.tolist(), b1.tolist()
