/**
* SVG chart generation utilities
*/

class ChartGenerator {
  pointOnCircle(cx, cy, r, angleDeg) {
    const rad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + r * Math.cos(rad),
      y: cy + r * Math.sin(rad),
    };
  }

  generatePieSvg(counts, colors, radius = 80, cx = 100, cy = 100) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return '';

    const items = Object.entries(counts).filter(([, cnt]) => cnt > 0);

    if (items.length === 1) {
      const [label] = items[0];
      const color = colors[label];
      return `<circle cx="${cx}" cy="${cy}" r="${radius}" fill="${color.fill}" stroke="${color.stroke}" stroke-width="2"/>`;
    }

    const paths = [];
    let angle = -90;

    for (const [label, cnt] of items) {
      const sweep = (360 * cnt) / total;
      const endAngle = angle + sweep;
      const p1 = this.pointOnCircle(cx, cy, radius, angle);
      const p2 = this.pointOnCircle(cx, cy, radius, endAngle);
      const largeArc = sweep > 180 ? 1 : 0;
      const color = colors[label];

      const pathData = `M ${cx},${cy} L ${p1.x.toFixed(4)},${p1.y.toFixed(4)} A ${radius},${radius} 0 ${largeArc},1 ${p2.x.toFixed(4)},${p2.y.toFixed(4)} Z`;
      paths.push(
        `<path d="${pathData}" fill="${color.fill}" stroke="${color.stroke}" stroke-width="2"/>`
      );

      angle = endAngle;
    }

    return paths.join('\n');
  }
}

module.exports = { ChartGenerator };
