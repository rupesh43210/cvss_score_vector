// Helper function to check if a string might be part of a CVSS vector
const isCVSSMetricPart = (str) => {
  if (!str) return false;
  str = str.toString().trim().toUpperCase();
  
  // Check for common CVSS metric patterns
  const isMetric = (
    /^(?:CVSS:3\.[01]\/)?[A-Z]+:[A-Z]+$/i.test(str) ||
    /^(?:AV|AC|PR|UI|S|C|I|A|E|RL|RC|CR|IR|AR|MAV|MAC|MPR|MUI|MS|MC|MI|MA):[A-Z]+$/i.test(str) ||
    /^(?:VECTOR|CVSS|SCORE|METRIC|SEVERITY)$/i.test(str)
  );

  console.log('Checking metric part:', str, 'Result:', isMetric);
  return isMetric;
};

// Function to extract potential CVSS vector parts from a string
const extractVectorParts = (str) => {
  if (!str) return [];
  str = str.toString().trim();
  
  console.log('Extracting parts from:', str);

  // If it's already a complete CVSS vector, return it as is
  if (/^CVSS:3\.[01]\/[A-Z]+:[A-Z]+(?:\/[A-Z]+:[A-Z]+)*$/i.test(str)) {
    console.log('Complete vector found:', str);
    return [str];
  }

  // Common separators in CVSS vectors
  const separators = ['/','|',',',';',' '];
  let parts = [str];
  
  // Try each separator
  for (const sep of separators) {
    if (str.includes(sep)) {
      parts = str.split(sep).map(p => p.trim()).filter(Boolean);
      // If we found parts that look like CVSS metrics, use these
      if (parts.some(p => isCVSSMetricPart(p))) {
        console.log('Found metric parts using separator', sep, ':', parts);
        break;
      }
    }
  }
  
  console.log('Extracted parts:', parts);
  return parts;
};

// Function to detect if a string contains a CVSS vector pattern
const detectCVSSPattern = (str) => {
  if (!str) return false;
  str = str.toString().trim().toUpperCase();
  
  console.log('Detecting pattern in:', str);

  // Direct match for complete CVSS vectors
  if (/^CVSS:3\.[01]\/[A-Z]+:[A-Z]+(?:\/[A-Z]+:[A-Z]+)*$/i.test(str)) {
    console.log('Found complete vector pattern');
    return true;
  }
  
  // Direct patterns that indicate CVSS content
  const cvssPatterns = [
    /CVSS(?:v|:)?3\.[01]/i,
    /AV:[NALP]/i,
    /AC:[LH]/i,
    /PR:[NLH]/i,
    /UI:[NR]/i,
    /S:[UC]/i,
    /C:[NLH]/i,
    /I:[NLH]/i,
    /A:[NLH]/i,
    /VECTOR:[^]*?(?:AV|AC|PR|UI|S|C|I|A):/i,
    /BASE_SCORE.*VECTOR/i,
    /[A-Z]+:[A-Z]+\/[A-Z]+:[A-Z]+/i,
    /^CVSS\s*VECTOR$/i,
    /^VECTOR\s*STRING$/i,
    /^BASE\s*VECTOR$/i
  ];
  
  for (const pattern of cvssPatterns) {
    if (pattern.test(str)) {
      console.log('Found CVSS pattern:', pattern);
      return true;
    }
  }

  // Check for multiple CVSS metric patterns
  const parts = extractVectorParts(str);
  const cvssMetricCount = parts.filter(isCVSSMetricPart).length;
  
  console.log('Found', cvssMetricCount, 'metric parts');
  return cvssMetricCount >= 2;
};

export const normalizeVector = (vector) => {
  try {
    if (!vector) return null;
    
    console.log('Normalizing vector:', vector);
    
    // Clean up the vector string
    vector = vector.toString().trim().toUpperCase();
    
    // If it's already a complete valid vector, return it
    if (/^CVSS:3\.[01]\/(?:AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH])(?:\/E:[UPFH]\/RL:[OTWU]\/RC:[URC])?(?:\/CR:[LMH]\/IR:[LMH]\/AR:[LMH])?(?:\/MAV:[NALP]\/MAC:[LH]\/MPR:[NLH]\/MUI:[NR]\/MS:[UC]\/MC:[NLH]\/MI:[NLH]\/MA:[NLH])?$/.test(vector)) {
      console.log('Vector already valid:', vector);
      return vector;
    }

    // Extract version - default to 3.1 if not specified
    let version = '3.1';
    const versionMatch = vector.match(/CVSS:3\.([01])/i);
    if (versionMatch) {
      version = versionMatch[1];
      vector = vector.replace(/CVSS:3\.[01]\//i, '');
      console.log('Found version:', version);
    }

    // Split into metrics
    const metrics = vector.split(/[/|,;\s]+/)
      .map(part => part.trim())
      .filter(Boolean)
      .filter(part => /^[A-Z]+:[A-Z]+$/i.test(part));

    console.log('Split metrics:', metrics);

    if (metrics.length < 3) {
      console.log('Not enough valid metrics found');
      return null;
    }

    // Validate and normalize each metric
    const normalizedMetrics = new Map();
    
    // Common value corrections
    const valueCorrections = {
      'NETWORK': 'N', 'ADJACENT': 'A', 'LOCAL': 'L', 'PHYSICAL': 'P',
      'LOW': 'L', 'HIGH': 'H', 'MEDIUM': 'H',
      'NONE': 'N', 'REQUIRED': 'R',
      'UNCHANGED': 'U', 'CHANGED': 'C',
      'PARTIAL': 'L', 'COMPLETE': 'H'
    };

    for (const metric of metrics) {
      const [type, originalValue] = metric.split(':');
      let value = originalValue;

      // Try to correct common value variations
      if (valueCorrections[value]) {
        value = valueCorrections[value];
        console.log('Corrected value:', originalValue, '->', value);
      }

      // Validate metric type and value
      const valid = validateMetric(type, value);
      if (valid) {
        normalizedMetrics.set(type, `${type}:${value}`);
        console.log('Valid metric:', type, value);
      } else {
        console.log('Invalid metric:', type, value);
      }
    }

    // Check if we have all required base metrics
    const requiredMetrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    for (const metric of requiredMetrics) {
      if (!normalizedMetrics.has(metric)) {
        // Try to set default values for missing metrics
        const defaultValue = getDefaultValue(metric);
        normalizedMetrics.set(metric, `${metric}:${defaultValue}`);
        console.log('Added default metric:', metric, defaultValue);
      }
    }

    // Order metrics properly
    const orderedMetrics = [
      'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A',
      'E', 'RL', 'RC',
      'CR', 'IR', 'AR',
      'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'
    ];

    // Build the normalized vector string
    const normalizedParts = [];
    for (const metric of orderedMetrics) {
      if (normalizedMetrics.has(metric)) {
        normalizedParts.push(normalizedMetrics.get(metric));
      }
    }

    const finalVector = `CVSS:3.${version}/` + normalizedParts.join('/');
    console.log('Final normalized vector:', finalVector);
    return finalVector;

  } catch (error) {
    console.error('Error normalizing vector:', error);
    return null;
  }
};

// Helper function to validate individual metrics
const validateMetric = (type, value) => {
  const validValues = {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'R'],
    S: ['U', 'C'],
    C: ['N', 'L', 'H'],
    I: ['N', 'L', 'H'],
    A: ['N', 'L', 'H'],
    E: ['U', 'P', 'F', 'H'],
    RL: ['O', 'T', 'W', 'U'],
    RC: ['U', 'R', 'C'],
    CR: ['L', 'M', 'H'],
    IR: ['L', 'M', 'H'],
    AR: ['L', 'M', 'H'],
    MAV: ['N', 'A', 'L', 'P'],
    MAC: ['L', 'H'],
    MPR: ['N', 'L', 'H'],
    MUI: ['N', 'R'],
    MS: ['U', 'C'],
    MC: ['N', 'L', 'H'],
    MI: ['N', 'L', 'H'],
    MA: ['N', 'L', 'H']
  };

  return validValues[type] && validValues[type].includes(value);
};

// Helper function to get default values for metrics
const getDefaultValue = (metric) => {
  const defaults = {
    AV: 'N',
    AC: 'L',
    PR: 'N',
    UI: 'N',
    S: 'U',
    C: 'N',
    I: 'N',
    A: 'N'
  };
  return defaults[metric] || 'N';
};

export const findVectorInRow = (row) => {
  // Helper function to check a single value for vectors
  const findVectorInValue = (value) => {
    if (!value || typeof value !== 'string') return null;
    value = value.trim();
    
    console.log('Checking value for vector:', value);

    // Skip obviously non-vector content
    if (value.length < 5) return null;
    if (/^\d+(?:\.\d+)?$/.test(value)) return null;
    if (/^https?:\/\//.test(value)) return null;
    if (value.length > 500) return null;

    // Direct match for complete CVSS vectors
    if (/^CVSS:3\.[01]\/[A-Z]+:[A-Z]+(?:\/[A-Z]+:[A-Z]+)*$/i.test(value)) {
      console.log('Found complete vector:', value);
      return normalizeVector(value);
    }

    // Check for direct CVSS patterns
    if (detectCVSSPattern(value)) {
      const parts = extractVectorParts(value);
      const metrics = parts.filter(isCVSSMetricPart);
      
      console.log('Found metrics:', metrics);
      
      if (metrics.length >= 2) {
        const vector = value.startsWith('CVSS:3') ? value : 'CVSS:3.1/' + metrics.join('/');
        console.log('Constructed vector:', vector);
        const normalized = normalizeVector(vector);
        if (normalized) {
          console.log('Successfully normalized vector:', normalized);
          return normalized;
        }
      }
    }

    return null;
  };

  try {
    console.log('Processing row:', row);

    // Special handling for common Excel formats
    if (row['CVSS Vector'] || row['Vector'] || row['CVSS']) {
      const vectorCell = row['CVSS Vector'] || row['Vector'] || row['CVSS'];
      console.log('Found vector in dedicated column:', vectorCell);
      const vector = findVectorInValue(vectorCell?.toString());
      if (vector) return vector;
    }

    // If row is a string or array, join it
    if (typeof row === 'string' || Array.isArray(row)) {
      const value = Array.isArray(row) ? row.join(' ') : row;
      return findVectorInValue(value);
    }

    // If row is an object with a 'cell' property
    if (row.cell) {
      return findVectorInValue(row.cell);
    }

    // Process each cell in the row
    for (const key in row) {
      const value = row[key];
      if (!value) continue;

      // Try to find vector in the cell value
      const vectorFromValue = findVectorInValue(value.toString());
      if (vectorFromValue) return vectorFromValue;

      // Try combining column name with value
      if (key) {
        const combinedValue = `${key}:${value}`;
        const vectorFromCombined = findVectorInValue(combinedValue);
        if (vectorFromCombined) return vectorFromCombined;
      }
    }

    // If no direct vector found, try to construct from parts
    const allParts = [];
    for (const key in row) {
      const value = row[key];
      if (!value) continue;

      const parts = value.toString()
        .split(/[/|,;\s]+/)
        .map(p => p.trim())
        .filter(Boolean);

      allParts.push(...parts);

      if (key) {
        const keyParts = key.toString()
          .split(/[_\s-]+/)
          .map(p => p.trim())
          .filter(Boolean);
        allParts.push(...keyParts);
      }
    }

    console.log('All parts found:', allParts);

    // Look for metric patterns in all parts
    const metrics = new Set();
    allParts.forEach(part => {
      if (isCVSSMetricPart(part)) {
        metrics.add(part.toUpperCase());
      } else {
        const metric = guessMetricFromPart(part);
        if (metric) metrics.add(metric);
      }
    });

    if (metrics.size >= 2) {
      const vector = 'CVSS:3.1/' + Array.from(metrics).join('/');
      console.log('Constructed vector from parts:', vector);
      const normalized = normalizeVector(vector);
      if (normalized) {
        console.log('Successfully normalized constructed vector:', normalized);
        return normalized;
      }
    }

  } catch (error) {
    console.error('Error in findVectorInRow:', error);
  }

  return null;
};

// Helper function to guess metrics from parts
const guessMetricFromPart = (part) => {
  if (!part) return null;
  part = part.toString().trim().toUpperCase();

  const metricGuesses = {
    AV: {
      patterns: [/^(?:ATTACK|ACCESS)[\s_-]?VECTOR$/i, /^VECTOR$/i, /^AV$/i],
      values: {
        NETWORK: 'N', ADJACENT: 'A', LOCAL: 'L', PHYSICAL: 'P',
        NET: 'N', ADJ: 'A', LOC: 'L', PHY: 'P',
        N: 'N', A: 'A', L: 'L', P: 'P'
      }
    },
    AC: {
      patterns: [/^(?:ATTACK|ACCESS)[\s_-]?COMPLEXITY$/i, /^COMPLEXITY$/i, /^AC$/i],
      values: {
        LOW: 'L', HIGH: 'H', MEDIUM: 'H',
        SIMPLE: 'L', COMPLEX: 'H',
        L: 'L', H: 'H', M: 'H'
      }
    },
    PR: {
      patterns: [/^PRIVILEGES[\s_-]?REQUIRED$/i, /^PRIVILEGE$/i, /^PR$/i],
      values: {
        NONE: 'N', LOW: 'L', HIGH: 'H',
        NO: 'N', YES: 'L',
        N: 'N', L: 'L', H: 'H'
      }
    },
    UI: {
      patterns: [/^USER[\s_-]?INTERACTION$/i, /^INTERACTION$/i, /^UI$/i],
      values: {
        NONE: 'N', REQUIRED: 'R',
        NO: 'N', YES: 'R',
        N: 'N', R: 'R'
      }
    },
    S: {
      patterns: [/^SCOPE$/i, /^S$/i],
      values: {
        UNCHANGED: 'U', CHANGED: 'C',
        NO: 'U', YES: 'C',
        U: 'U', C: 'C'
      }
    },
    C: {
      patterns: [/^CONFIDENTIALITY$/i, /^CONF$/i, /^C$/i],
      values: {
        NONE: 'N', LOW: 'L', HIGH: 'H',
        NO: 'N', PARTIAL: 'L', COMPLETE: 'H',
        N: 'N', L: 'L', H: 'H'
      }
    },
    I: {
      patterns: [/^INTEGRITY$/i, /^INT$/i, /^I$/i],
      values: {
        NONE: 'N', LOW: 'L', HIGH: 'H',
        NO: 'N', PARTIAL: 'L', COMPLETE: 'H',
        N: 'N', L: 'L', H: 'H'
      }
    },
    A: {
      patterns: [/^AVAILABILITY$/i, /^AVAIL$/i, /^A$/i],
      values: {
        NONE: 'N', LOW: 'L', HIGH: 'H',
        NO: 'N', PARTIAL: 'L', COMPLETE: 'H',
        N: 'N', L: 'L', H: 'H'
      }
    }
  };

  for (const [metric, { patterns, values }] of Object.entries(metricGuesses)) {
    // Check if part matches any pattern for this metric
    if (patterns.some(pattern => pattern.test(part))) {
      // Look for a value in nearby text
      for (const [fullValue, shortValue] of Object.entries(values)) {
        if (part.includes(fullValue) || fullValue.includes(part)) {
          return `${metric}:${shortValue}`;
        }
      }
    }
  }

  return null;
};

export const parseVectorFromColumns = (row) => {
  const metrics = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  const vectorParts = [];
  
  // Common column name variations
  const columnVariations = {
    AV: ['attack_vector', 'attackvector', 'attack vector', 'vector', 'av_score'],
    AC: ['attack_complexity', 'attackcomplexity', 'attack complexity', 'complexity', 'ac_score'],
    PR: ['privileges_required', 'privilegesrequired', 'privileges', 'privilege', 'pr_score'],
    UI: ['user_interaction', 'userinteraction', 'user', 'interaction', 'ui_score'],
    S: ['scope', 'scope_score', 'scope_changed'],
    C: ['confidentiality', 'confidentiality_impact', 'conf', 'c_score'],
    I: ['integrity', 'integrity_impact', 'integ', 'i_score'],
    A: ['availability', 'availability_impact', 'avail', 'a_score']
  };
  
  // Try to find individual metric columns
  metrics.forEach(metric => {
    // Look for exact match first
    let value = row[metric] || row[metric.toLowerCase()];
    
    // If not found, try variations
    if (!value && columnVariations[metric]) {
      for (const variation of columnVariations[metric]) {
        // Try different case variations
        const possibleKeys = [
          variation,
          variation.toUpperCase(),
          variation.toLowerCase(),
          variation.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()).join('')
        ];
        
        for (const key of possibleKeys) {
          if (row[key] !== undefined) {
            value = row[key];
            break;
          }
        }
        if (value) break;
      }
    }
                 
    if (value) {
      const guessedValue = guessMetricValue(metric, value);
      if (guessedValue) {
        vectorParts.push(`${metric}:${guessedValue}`);
      }
    }
  });
  
  if (vectorParts.length > 0) {
    return 'CVSS:3.1/' + vectorParts.join('/');
  }
  
  return null;
};

export const guessMetricValue = (metric, value) => {
  const metricMappings = {
    AV: {
      'NETWORK': 'N', 'ADJACENT': 'A', 'LOCAL': 'L', 'PHYSICAL': 'P',
      'ADJACENT_NETWORK': 'A', 'LOCAL_ACCESS': 'L', 'PHYSICAL_ACCESS': 'P',
      'NET': 'N', 'ADJ': 'A', 'LOC': 'L', 'PHY': 'P',
      'N': 'N', 'A': 'A', 'L': 'L', 'P': 'P'
    },
    AC: {
      'LOW': 'L', 'HIGH': 'H', 'MEDIUM': 'H',
      'SIMPLE': 'L', 'COMPLEX': 'H',
      'L': 'L', 'H': 'H', 'M': 'H'
    },
    PR: {
      'NONE': 'N', 'LOW': 'L', 'HIGH': 'H',
      'NOT_REQUIRED': 'N', 'REQUIRED': 'L', 'HIGH_PRIVILEGE': 'H',
      'N': 'N', 'L': 'L', 'H': 'H'
    },
    UI: {
      'NONE': 'N', 'REQUIRED': 'R',
      'NOT_REQUIRED': 'N', 'USER_INTERACTION': 'R',
      'NO': 'N', 'YES': 'R',
      'N': 'N', 'R': 'R'
    },
    S: {
      'UNCHANGED': 'U', 'CHANGED': 'C',
      'NO': 'U', 'YES': 'C',
      'NONE': 'U', 'CHANGE': 'C',
      'U': 'U', 'C': 'C'
    },
    C: {
      'NONE': 'N', 'LOW': 'L', 'HIGH': 'H',
      'NO': 'N', 'PARTIAL': 'L', 'COMPLETE': 'H',
      'N': 'N', 'L': 'L', 'H': 'H'
    },
    I: {
      'NONE': 'N', 'LOW': 'L', 'HIGH': 'H',
      'NO': 'N', 'PARTIAL': 'L', 'COMPLETE': 'H',
      'N': 'N', 'L': 'L', 'H': 'H'
    },
    A: {
      'NONE': 'N', 'LOW': 'L', 'HIGH': 'H',
      'NO': 'N', 'PARTIAL': 'L', 'COMPLETE': 'H',
      'N': 'N', 'L': 'L', 'H': 'H'
    }
  };

  if (!value) return null;
  
  const upperValue = value.toString().toUpperCase().trim();
  return metricMappings[metric]?.[upperValue] || null;
};
