export class CVSSCalculator {
  constructor(vector) {
    console.log('Initializing CVSSCalculator with vector:', vector);
    this.vector = vector;
    this.metrics = this.parseVector(vector);
    console.log('Parsed metrics:', this.metrics);
  }

  parseVector(vector) {
    try {
      if (!vector) {
        console.log('Vector is empty');
        return null;
      }

      // Clean and normalize the vector
      vector = vector.toString().trim().toUpperCase();
      console.log('Normalized vector:', vector);

      // Extract version and validate format
      const versionMatch = vector.match(/^CVSS:3\.[01]/i);
      if (!versionMatch) {
        console.log('Invalid vector format - must start with CVSS:3.0 or CVSS:3.1');
        return null;
      }

      // Remove version prefix for parsing
      const metricsString = vector.substring(vector.indexOf('/') + 1);
      console.log('Metrics string:', metricsString);

      const metrics = {};
      const parts = metricsString.split('/');
      console.log('Vector parts:', parts);

      // Parse each metric
      for (const part of parts) {
        const [metric, value] = part.split(':');
        if (!metric || !value) {
          console.log('Invalid metric format:', part);
          return null;
        }
        metrics[metric] = value;
      }

      // Validate required base metrics
      const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
      for (const metric of requiredMetrics) {
        if (!metrics[metric]) {
          console.log('Missing required metric:', metric);
          return null;
        }
      }

      // Set default values for temporal metrics if not present
      const temporalMetrics = ['E', 'RL', 'RC'];
      temporalMetrics.forEach(metric => {
        if (!metrics[metric]) metrics[metric] = 'X';
      });

      // Set default values for environmental metrics if not present
      const environmentalMetrics = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
      environmentalMetrics.forEach(metric => {
        if (!metrics[metric]) metrics[metric] = 'X';
      });

      // Validate all metric values
      if (!this.validateMetricValues(metrics)) {
        console.log('Invalid metric values found');
        return null;
      }

      console.log('Successfully parsed metrics:', metrics);
      return metrics;
    } catch (error) {
      console.error('Error parsing vector:', error);
      return null;
    }
  }

  validateMetricValues(metrics) {
    const validValues = {
      // Base Score Metrics
      AV: ['N', 'A', 'L', 'P'],
      AC: ['L', 'H'],
      PR: ['N', 'L', 'H'],
      UI: ['N', 'R'],
      S: ['U', 'C'],
      C: ['N', 'L', 'H'],
      I: ['N', 'L', 'H'],
      A: ['N', 'L', 'H'],
      // Temporal Score Metrics
      E: ['X', 'U', 'P', 'F', 'H'],
      RL: ['X', 'O', 'T', 'W', 'U'],
      RC: ['X', 'U', 'R', 'C'],
      // Environmental Score Metrics
      CR: ['X', 'L', 'M', 'H'],
      IR: ['X', 'L', 'M', 'H'],
      AR: ['X', 'L', 'M', 'H'],
      MAV: ['X', 'N', 'A', 'L', 'P'],
      MAC: ['X', 'L', 'H'],
      MPR: ['X', 'N', 'L', 'H'],
      MUI: ['X', 'N', 'R'],
      MS: ['X', 'U', 'C'],
      MC: ['X', 'N', 'L', 'H'],
      MI: ['X', 'N', 'L', 'H'],
      MA: ['X', 'N', 'L', 'H']
    };

    for (const [metric, value] of Object.entries(metrics)) {
      if (validValues[metric]) {
        if (!validValues[metric].includes(value)) {
          console.log(`Invalid value for ${metric}: ${value}`);
          console.log(`Valid values are: ${validValues[metric].join(', ')}`);
          return false;
        }
      }
    }

    return true;
  }

  calculateScores() {
    try {
      if (!this.metrics) {
        console.log('No valid metrics to calculate score');
        return null;
      }

      // Calculate Base Score
      const baseScore = this.calculateBaseScore();
      if (baseScore === null) return null;

      // Calculate Temporal Score
      const temporalScore = this.calculateTemporalScore(baseScore);

      // Calculate Environmental Score
      const environmentalScore = this.calculateEnvironmentalScore();

      // Calculate Impact Scores
      const impactScores = this.calculateImpactScores();

      return {
        baseScore: baseScore.toFixed(1),
        temporalScore: temporalScore.toFixed(1),
        environmentalScore: environmentalScore.toFixed(1),
        impactScores,
        severity: this.getSeverity(baseScore)
      };
    } catch (error) {
      console.error('Error calculating scores:', error);
      return null;
    }
  }

  calculateBaseScore() {
    try {
      const {
        AV: attackVector,
        AC: attackComplexity,
        PR: privilegesRequired,
        UI: userInteraction,
        S: scope,
        C: confidentiality,
        I: integrity,
        A: availability
      } = this.metrics;

      // Metric weights
      const weights = {
        AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
        AC: { L: 0.77, H: 0.44 },
        PR: {
          U: { N: 0.85, L: 0.62, H: 0.27 },
          C: { N: 0.85, L: 0.68, H: 0.5 }
        },
        UI: { N: 0.85, R: 0.62 },
        C: { N: 0, L: 0.22, H: 0.56 },
        I: { N: 0, L: 0.22, H: 0.56 },
        A: { N: 0, L: 0.22, H: 0.56 }
      };

      // Calculate ISS (Impact Sub-Score)
      const iss = 1 - (
        (1 - weights.C[confidentiality]) *
        (1 - weights.I[integrity]) *
        (1 - weights.A[availability])
      );

      // Calculate Impact
      let impact;
      if (scope === 'U') {
        impact = 6.42 * iss;
      } else {
        impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
      }

      // Calculate Exploitability
      const exploitability = 8.22 * 
        weights.AV[attackVector] * 
        weights.AC[attackComplexity] * 
        weights.PR[scope][privilegesRequired] * 
        weights.UI[userInteraction];

      // Calculate Base Score
      let baseScore;
      if (impact <= 0) {
        baseScore = 0;
      } else if (scope === 'U') {
        baseScore = Math.min((impact + exploitability), 10);
      } else {
        baseScore = Math.min(1.08 * (impact + exploitability), 10);
      }

      return Math.ceil(baseScore * 10) / 10;
    } catch (error) {
      console.error('Error calculating base score:', error);
      return null;
    }
  }

  calculateTemporalScore(baseScore) {
    try {
      const { E, RL, RC } = this.metrics;

      // Temporal metric weights
      const weights = {
        E: { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 },
        RL: { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 },
        RC: { X: 1, U: 0.92, R: 0.96, C: 1 }
      };

      // Calculate temporal score
      const temporalScore = baseScore * 
        weights.E[E] * 
        weights.RL[RL] * 
        weights.RC[RC];

      return Math.ceil(temporalScore * 10) / 10;
    } catch (error) {
      console.error('Error calculating temporal score:', error);
      return baseScore;
    }
  }

  calculateEnvironmentalScore() {
    try {
      const {
        CR, IR, AR,
        MAV, MAC, MPR, MUI, MS, MC, MI, MA
      } = this.metrics;

      // Environmental metric weights
      const weights = {
        CR: { X: 1, L: 0.5, M: 1, H: 1.5 },
        IR: { X: 1, L: 0.5, M: 1, H: 1.5 },
        AR: { X: 1, L: 0.5, M: 1, H: 1.5 },
        AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
        AC: { L: 0.77, H: 0.44 },
        PR: {
          U: { N: 0.85, L: 0.62, H: 0.27 },
          C: { N: 0.85, L: 0.68, H: 0.5 }
        },
        UI: { N: 0.85, R: 0.62 },
        CIA: { N: 0, L: 0.22, H: 0.56 }
      };

      // Use modified metrics if specified, otherwise use base metrics
      const av = MAV === 'X' ? this.metrics.AV : MAV;
      const ac = MAC === 'X' ? this.metrics.AC : MAC;
      const pr = MPR === 'X' ? this.metrics.PR : MPR;
      const ui = MUI === 'X' ? this.metrics.UI : MUI;
      const s = MS === 'X' ? this.metrics.S : MS;
      const c = MC === 'X' ? this.metrics.C : MC;
      const i = MI === 'X' ? this.metrics.I : MI;
      const a = MA === 'X' ? this.metrics.A : MA;

      // Calculate modified impact
      const modifiedIss = Math.min(1 - (
        (1 - weights.CIA[c] * weights.CR[CR]) *
        (1 - weights.CIA[i] * weights.IR[IR]) *
        (1 - weights.CIA[a] * weights.AR[AR])
      ), 0.915);

      // Calculate modified impact score
      let modifiedImpact;
      if (s === 'U') {
        modifiedImpact = 6.42 * modifiedIss;
      } else {
        modifiedImpact = 7.52 * (modifiedIss - 0.029) - 3.25 * Math.pow(modifiedIss * 0.9731 - 0.02, 13);
      }

      // Calculate modified exploitability
      const modifiedExploitability = 8.22 * 
        weights.AV[av] * 
        weights.AC[ac] * 
        weights.PR[s][pr] * 
        weights.UI[ui];

      // Calculate environmental score
      let environmentalScore;
      if (modifiedImpact <= 0) {
        environmentalScore = 0;
      } else if (s === 'U') {
        environmentalScore = Math.min((modifiedImpact + modifiedExploitability), 10);
      } else {
        environmentalScore = Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10);
      }

      return Math.ceil(environmentalScore * 10) / 10;
    } catch (error) {
      console.error('Error calculating environmental score:', error);
      return null;
    }
  }

  calculateImpactScores() {
    try {
      const { C, I, A, CR, IR, AR } = this.metrics;

      // Impact metric weights
      const weights = {
        CIA: { N: 0, L: 0.22, H: 0.56 },
        MOD: { X: 1, L: 0.5, M: 1, H: 1.5 }
      };

      // Calculate confidentiality impact
      const confImpact = weights.CIA[C] * (CR === 'X' ? 1 : weights.MOD[CR]);
      
      // Calculate integrity impact
      const integImpact = weights.CIA[I] * (IR === 'X' ? 1 : weights.MOD[IR]);
      
      // Calculate availability impact
      const availImpact = weights.CIA[A] * (AR === 'X' ? 1 : weights.MOD[AR]);

      return {
        confidentialityImpact: confImpact.toFixed(2),
        integrityImpact: integImpact.toFixed(2),
        availabilityImpact: availImpact.toFixed(2)
      };
    } catch (error) {
      console.error('Error calculating impact scores:', error);
      return null;
    }
  }

  getSeverity(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score > 0.0) return 'Low';
    return 'None';
  }

  getQualitativeMetrics() {
    const metrics = this.metrics;
    if (!metrics) return null;

    const descriptions = {
      AV: {
        N: 'Network',
        A: 'Adjacent',
        L: 'Local',
        P: 'Physical'
      },
      AC: {
        L: 'Low',
        H: 'High'
      },
      PR: {
        N: 'None',
        L: 'Low',
        H: 'High'
      },
      UI: {
        N: 'None',
        R: 'Required'
      },
      S: {
        U: 'Unchanged',
        C: 'Changed'
      },
      CIA: {
        N: 'None',
        L: 'Low',
        H: 'High'
      },
      E: {
        X: 'Not Defined',
        U: 'Unproven',
        P: 'Proof-of-Concept',
        F: 'Functional',
        H: 'High'
      },
      RL: {
        X: 'Not Defined',
        O: 'Official Fix',
        T: 'Temporary Fix',
        W: 'Workaround',
        U: 'Unavailable'
      },
      RC: {
        X: 'Not Defined',
        U: 'Unknown',
        R: 'Reasonable',
        C: 'Confirmed'
      }
    };

    return {
      attackVector: descriptions.AV[metrics.AV],
      attackComplexity: descriptions.AC[metrics.AC],
      privilegesRequired: descriptions.PR[metrics.PR],
      userInteraction: descriptions.UI[metrics.UI],
      scope: descriptions.S[metrics.S],
      confidentiality: descriptions.CIA[metrics.C],
      integrity: descriptions.CIA[metrics.I],
      availability: descriptions.CIA[metrics.A],
      exploitCodeMaturity: descriptions.E[metrics.E],
      remediationLevel: descriptions.RL[metrics.RL],
      reportConfidence: descriptions.RC[metrics.RC]
    };
  }
}
