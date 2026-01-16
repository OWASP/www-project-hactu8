import React, { useState } from 'react';

const SmartFrame = ({
  src,
  title = "SmartIframe",
  style = {},
  ...props
}: {
  src: string;
  title?: string;
  style?: React.CSSProperties;
  [key: string]: any;
}) => {
  const [loaded, setLoaded] = useState(false);

  const containerStyle: React.CSSProperties = {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: '#000',
    ...style,
  };

  const iframeStyle: React.CSSProperties = {
    width: '100%',
    height: '100%',
    border: 'none',
    opacity: loaded ? 1 : 0,
    transition: 'opacity 0.3s ease-in-out',
  };

  const loaderStyle: React.CSSProperties = {
    backgroundColor: '#000',
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    zIndex: 1,
    display: loaded ? 'none' : 'block',
  };

  return (
    <div style={containerStyle}>
      <div style={loaderStyle} />
      <iframe
        title={title}
        src={src}
        style={iframeStyle}
        onLoad={() => setLoaded(true)}
        {...props}
      />
    </div>
  );
};

export default SmartFrame;