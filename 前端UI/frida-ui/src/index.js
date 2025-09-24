import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import './App.css';

// 启用React的并发模式（如果可用）
const rootElement = document.getElementById('root');

// 添加错误边界
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error("应用发生错误:", error, errorInfo);
    this.setState({
      error: error,
      errorInfo: errorInfo
    });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '20px', color: '#f00' }}>
          <h1>应用发生错误</h1>
          <details style={{ whiteSpace: 'pre-wrap' }}>
            {this.state.error && this.state.error.toString()}
            <br />
            {this.state.errorInfo && this.state.errorInfo.componentStack}
          </details>
        </div>
      );
    }

    return this.props.children;
  }
}

// 启用生产环境优化
if (process.env.NODE_ENV === 'production') {
  // 禁用开发警告
  console.disableYellowBox = true;
}

// 使用createRoot API (React 18+) 如果可用
if (ReactDOM.createRoot) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
} else {
  // 兼容旧版本React
  ReactDOM.render(
    <ErrorBoundary>
      <App />
    </ErrorBoundary>,
    rootElement
  );
}