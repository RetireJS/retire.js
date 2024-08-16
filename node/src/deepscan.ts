import { multiQuery } from 'astronomical';
import { Component, Repository } from './types';
import { check } from './retire';

export function deepScan(content: string, repo: Repository): Component[] {
  const astQueries: Record<string, string> = {};
  const backMap: Record<string, string> = {};
  Object.entries(repo).forEach(([name, data]) => {
    data.extractors.ast?.forEach((query, i) => {
      astQueries[`${name}_${i}`] = query;
      backMap[`${name}_${i}`] = name;
    });
  });
  const results = multiQuery(content, astQueries) as Record<string, []>;
  const detected: Component[] = [];
  Object.entries(results).forEach(([key, value]) => {
    value.forEach((match) => {
      const component = backMap[key];
      if (typeof match !== 'string') return;
      detected.push({
        version: match,
        component: component,
        npmname: repo[component].npmname,
        basePurl: repo[component].basePurl,
        detection: 'ast',
      });
    });
  });
  return detected.reduce((acc, cur) => {
    if (acc.some((c) => c.component === cur.component && c.version === cur.version)) return acc;
    return acc.concat(check(cur.component, cur.version, repo));
  }, [] as Component[]);
}
