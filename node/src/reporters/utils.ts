import { Component } from '../types';

function encodePURLchars(str: string): string {
  return str.replace(
    /[^A-Za-z0-9.+/=%-]/g,
    (match) => '%' + ('0' + match.charCodeAt(0).toString(16).toUpperCase()).slice(-2),
  );
}

export function generatePURL(component: Component): string {
  if (component.basePurl) {
    const [pType, ...rest] = component.basePurl.split(':');
    const pathElements = rest.join(':').split('/').map(encodePURLchars).join('/');
    return `${pType}:${pathElements}@${encodePURLchars(component.version)}`;
  }
  const compName = component.npmname || component.component;
  return `pkg:npm/${encodePURLchars(compName)}@${encodePURLchars(component.version)}`;
}
