import React from 'react';
import { Resizable } from 'react-resizable';
import 'react-resizable/css/styles.css';

const ResizableTitle = (props) => {
  const { onResize, width, ...restProps } = props;

  if (!width) {
    return <th {...restProps} />;
  }

  return (
    <Resizable
      width={width}
      height={0}
      handle={
        <span
          className="react-resizable-handle"
          onClick={(e) => {
            e.stopPropagation();
          }}
        />
      }
      onResize={onResize}
      draggableOpts={{ enableUserSelectHack: false }}
      style={{ display: 'table-cell', width: '100%' }}
    >
      <th {...restProps} style={{ 
        width: `${width}px`, 
        display: 'table-cell',
        padding: '16px',
        boxSizing: 'border-box'
      }} />
    </Resizable>
  );
};

export default ResizableTitle;