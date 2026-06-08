import React, { useEffect, useRef } from "react";
import * as d3 from "d3";

const colorBySeverity = {
  info: "#7f8ea3",
  low: "#52b788",
  medium: "#f4a261",
  high: "#e76f51",
  critical: "#d62828"
};

function radiusFor(datum) {
  if (datum.kind === "finding") return 13;
  if (datum.kind === "role") return 18;
  return 22;
}

export default function AttackGraph({ graph }) {
  const ref = useRef(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    root.innerHTML = "";

    const width = root.clientWidth || 900;
    const height = 520;
    const svg = d3
      .select(root)
      .append("svg")
      .attr("viewBox", `0 0 ${width} ${height}`)
      .attr("role", "img");

    const nodes = (graph?.nodes || []).map((node) => ({ ...node }));
    const links = (graph?.edges || []).map((edge) => ({ ...edge }));

    if (!nodes.length) {
      svg
        .append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "#9aa7b3")
        .text("No graph data");
      return;
    }

    const simulation = d3
      .forceSimulation(nodes)
      .force(
        "link",
        d3
          .forceLink(links)
          .id((node) => node.id)
          .distance((link) => (link.label?.includes("escalation") ? 170 : 105))
      )
      .force("charge", d3.forceManyBody().strength(-420))
      .force("x", d3.forceX(width / 2).strength(0.08))
      .force("y", d3.forceY(height / 2).strength(0.08))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(48));

    const link = svg
      .append("g")
      .attr("stroke", "#3a4654")
      .attr("stroke-opacity", 0.9)
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke-width", (edge) => (edge.risk === "high" || edge.risk === "critical" ? 2.5 : 1.4))
      .attr("stroke", (edge) => colorBySeverity[edge.risk] || "#3a4654");

    const node = svg
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .call(
        d3
          .drag()
          .on("start", (event, datum) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            datum.fx = datum.x;
            datum.fy = datum.y;
          })
          .on("drag", (event, datum) => {
            datum.fx = event.x;
            datum.fy = event.y;
          })
          .on("end", (event, datum) => {
            if (!event.active) simulation.alphaTarget(0);
            datum.fx = null;
            datum.fy = null;
          })
      );

    node
      .append("circle")
      .attr("r", radiusFor)
      .attr("fill", (datum) => colorBySeverity[datum.severity] || "#7f8ea3")
      .attr("stroke", "#10141a")
      .attr("stroke-width", 2);

    node
      .filter((datum) => datum.kind !== "finding")
      .append("text")
      .attr("x", 28)
      .attr("y", 4)
      .attr("fill", "#e9eef5")
      .attr("font-size", 12)
      .text((datum) => trimLabel(datum.label));

    node.append("title").text((datum) => `${datum.kind}: ${datum.label}`);

    simulation.on("tick", () => {
      nodes.forEach((datum) => {
        const radius = radiusFor(datum) + 6;
        datum.x = Math.max(radius, Math.min(width - radius, datum.x));
        datum.y = Math.max(radius, Math.min(height - radius, datum.y));
      });

      link
        .attr("x1", (edge) => edge.source.x)
        .attr("y1", (edge) => edge.source.y)
        .attr("x2", (edge) => edge.target.x)
        .attr("y2", (edge) => edge.target.y);

      node
        .select("text")
        .attr("x", (datum) => (datum.x > width * 0.62 ? -28 : 28))
        .attr("text-anchor", (datum) => (datum.x > width * 0.62 ? "end" : "start"));

      node.attr("transform", (datum) => `translate(${datum.x},${datum.y})`);
    });

    return () => simulation.stop();
  }, [graph]);

  return <div className="graph-canvas" ref={ref} />;
}

function trimLabel(label = "") {
  return label.length > 42 ? `${label.slice(0, 39)}...` : label;
}
