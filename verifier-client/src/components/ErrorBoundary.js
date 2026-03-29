import React from 'react';

/**
 * ErrorBoundary
 * Wraps any subtree and catches uncaught render/lifecycle errors.
 *
 * Usage:
 *   <ErrorBoundary>
 *     <YourComponent />
 *   </ErrorBoundary>
 *
 * Optional props:
 *   fallback  – custom ReactElement to show in place of the broken tree
 *   onError   – callback(error, info) for external logging (e.g. Sentry)
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, info: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    this.setState({ info });
    if (typeof this.props.onError === 'function') {
      this.props.onError(error, info);
    } else {
      // Default: log to console so the trace is still visible in DevTools.
      console.error('[ErrorBoundary] Caught an unhandled error:', error, info);
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, info: null });
  };

  render() {
    const { hasError, error } = this.state;
    const { fallback, children } = this.props;

    if (!hasError) return children;

    // Custom fallback provided by the parent
    if (fallback) return fallback;

    // Default built-in fallback UI
    return (
      <div style={styles.container}>
        <div style={styles.card}>
          <h2 style={styles.heading}>Something went wrong</h2>
          <p style={styles.message}>
            An unexpected error occurred. You can try reloading the page or
            click the button below to reset this section.
          </p>
          {error && (
            <details style={styles.details}>
              <summary style={styles.summary}>Error details</summary>
              <pre style={styles.pre}>{error.toString()}</pre>
            </details>
          )}
          <button style={styles.button} onClick={this.handleReset}>
            Try Again
          </button>
        </div>
      </div>
    );
  }
}

// ---------------------------------------------------------------------------
// Inline styles – avoids any dependency on external CSS classes
// ---------------------------------------------------------------------------
const styles = {
  container: {
    display:        'flex',
    alignItems:     'center',
    justifyContent: 'center',
    minHeight:      '200px',
    padding:        '2rem',
  },
  card: {
    background:   '#161b22',
    border:       '1px solid #30363d',
    borderRadius: '8px',
    padding:      '2rem',
    maxWidth:     '600px',
    width:        '100%',
    textAlign:    'center',
    color:        '#e6edf3',
  },
  heading: {
    color:      '#f85149',
    marginTop:  0,
    fontSize:   '1.4rem',
  },
  message: {
    color:        '#8b949e',
    marginBottom: '1.5rem',
  },
  details: {
    textAlign:    'left',
    marginBottom: '1.5rem',
    background:   '#0d1117',
    border:       '1px solid #30363d',
    borderRadius: '6px',
    padding:      '0.75rem',
  },
  summary: {
    cursor:    'pointer',
    color:     '#8b949e',
    fontSize:  '0.875rem',
    userSelect: 'none',
  },
  pre: {
    color:      '#ff7b72',
    fontSize:   '0.8rem',
    overflow:   'auto',
    margin:     '0.5rem 0 0',
    whiteSpace: 'pre-wrap',
    wordBreak:  'break-word',
  },
  button: {
    background:   '#238636',
    color:        '#ffffff',
    border:       'none',
    borderRadius: '6px',
    padding:      '0.6rem 1.4rem',
    cursor:       'pointer',
    fontSize:     '0.95rem',
    fontWeight:   '600',
  },
};

export default ErrorBoundary;
