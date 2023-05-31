import { Component } from '../types';

export function generatePURL(component: Component): string {
  const compName = component.npmname || component.component;
  return `pkg:npm/${compName}@${component.version}`;
}
