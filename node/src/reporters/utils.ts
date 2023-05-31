import { Component } from '../types';

export function generatePURL(component: Component): string {
  if (component.basePurl) {
    return component.basePurl + '@' + component.version;
  }
  const compName = component.npmname || component.component;
  return `pkg:npm/${compName}@${component.version}`;
}
