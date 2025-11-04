import React from 'react';
import { Box, Typography, useTheme } from '@mui/material';
import DOMPurify from 'dompurify';

interface SafeHTMLRendererProps {
  html: string;
  variant?: 'body1' | 'body2' | 'caption';
  component?: React.ElementType;
  sx?: object;
}

/**
 * SafeHTMLRenderer - Safely renders HTML content from compliance rule descriptions
 *
 * Converts common HTML tags to Material-UI styled components:
 * - <tt> -> monospace code style
 * - <b> -> bold text
 * - <br /> -> line breaks
 * - <i> -> italic text
 *
 * Uses DOMPurify to sanitize HTML and prevent XSS attacks
 */
const SafeHTMLRenderer: React.FC<SafeHTMLRendererProps> = ({
  html,
  variant = 'body2',
  component = 'div',
  sx = {},
}) => {
  const theme = useTheme();

  // Sanitize HTML to prevent XSS
  const sanitizeHTML = (dirtyHTML: string): string => {
    return DOMPurify.sanitize(dirtyHTML, {
      ALLOWED_TAGS: ['tt', 'code', 'pre', 'b', 'strong', 'i', 'em', 'br', 'p', 'ul', 'ol', 'li'],
      ALLOWED_ATTR: [],
    });
  };

  // Convert HTML to styled content
  const renderHTML = (htmlContent: string) => {
    const cleanHTML = sanitizeHTML(htmlContent);

    // Custom CSS for HTML elements
    const htmlStyles = `
      tt, code {
        font-family: 'Roboto Mono', 'Courier New', monospace;
        background-color: ${theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.04)'};
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 0.9em;
        border: 1px solid ${theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)'};
      }

      b, strong {
        font-weight: 600;
      }

      i, em {
        font-style: italic;
      }

      p {
        margin: 0.5em 0;
      }

      p:first-child {
        margin-top: 0;
      }

      p:last-child {
        margin-bottom: 0;
      }

      ul, ol {
        margin: 0.5em 0;
        padding-left: 1.5em;
      }

      li {
        margin: 0.25em 0;
      }

      pre {
        font-family: 'Roboto Mono', 'Courier New', monospace;
        background-color: ${theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.04)'};
        padding: 12px;
        border-radius: 4px;
        overflow-x: auto;
        border: 1px solid ${theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.12)'};
      }
    `;

    return (
      <>
        <style>{htmlStyles}</style>
        <Typography
          variant={variant}
          component={component}
          sx={{
            lineHeight: 1.6,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            ...sx,
          }}
          dangerouslySetInnerHTML={{ __html: cleanHTML }}
        />
      </>
    );
  };

  return <Box>{renderHTML(html)}</Box>;
};

export default SafeHTMLRenderer;
