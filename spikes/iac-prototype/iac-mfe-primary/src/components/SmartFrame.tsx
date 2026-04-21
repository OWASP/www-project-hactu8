import React, { useEffect, useState } from 'react';
import './SmartFrame.css';

type SmartFrameProps = {
  src: string;
  title?: string;
  className?: string;
} & React.IframeHTMLAttributes<HTMLIFrameElement>;

const SmartFrame = ({
  src,
  title = 'SmartIframe',
  className,
  ...props
}: SmartFrameProps) => {
  const [loaded, setLoaded] = useState(false);
  const [timedOut, setTimedOut] = useState(false);

  useEffect(() => {
    setLoaded(false);
    setTimedOut(false);

    const timeout = window.setTimeout(() => {
      setTimedOut(true);
    }, 10000);

    return () => window.clearTimeout(timeout);
  }, [src]);

  return (
    <div className={['smart-frame-container', className].filter(Boolean).join(' ')}>
      <div className={loaded || timedOut ? 'smart-frame-loader is-hidden' : 'smart-frame-loader'} />
      <div className={timedOut && !loaded ? 'smart-frame-timeout' : 'smart-frame-timeout is-hidden'}>
        <div>
          <strong>Unable to load embedded app.</strong>
          <div>Check that this service is running: {src}</div>
        </div>
      </div>
      <iframe
        title={title}
        src={src}
        className={loaded ? 'smart-frame-iframe is-loaded' : 'smart-frame-iframe'}
        onLoad={() => setLoaded(true)}
        {...props}
      />
    </div>
  );
};

export default SmartFrame;