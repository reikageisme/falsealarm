import asyncio
import os
import yaml
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from falsealarm.modules.base import BaseModule, ModuleResult
from falsealarm.core.utils import get_data_path

class VulnScanModule(BaseModule):
    name = "vulnscan"
    description = "YAML-based Vulnerability Detection Engine"

    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        results: list[dict[str, Any]] = []
        stats = {"templates_loaded": 0, "vulns_found": 0, "requests_sent": 0}

        if not target.startswith("http"):
            target = f"http://{target}"

        # Ensure trailing slash removed for clean urljoin
        if target.endswith("/"):
            target = target[:-1]

        # Load templates
        templates_dir = get_data_path("templates")
        template_files = []
        
        if os.path.exists(templates_dir):
            for root, _, files in os.walk(templates_dir):
                for file in files:
                    if file.endswith((".yaml", ".yml")):
                        template_files.append(os.path.join(root, file))

        if not template_files:
            self.logger.warning(f"No YAML templates found in {templates_dir}")
            return self._make_result(target, results, stats)

        templates = []
        for t_file in template_files:
            try:
                with open(t_file, "r", encoding="utf-8") as f:
                    template_data = yaml.safe_load(f)
                    if template_data and "id" in template_data and "requests" in template_data:
                        templates.append(template_data)
                        stats["templates_loaded"] += 1
            except Exception as e:
                self.logger.error(f"Failed to load template {t_file}: {e}")

        self.logger.info(f"Loaded {stats['templates_loaded']} vulnerability templates. Scanning {target}...")

        sem = asyncio.Semaphore(self.config.threads)

        async def execute_template(template: dict):
            vulns = []
            for req in template.get("requests", []):
                method = req.get("method", "GET")
                path = req.get("path", "/")
                
                # Dynamic placeholder support in path
                if "{{BaseURL}}" in path:
                    test_url = path.replace("{{BaseURL}}", target)
                else:
                    test_url = target + path

                headers = req.get("headers", {})
                matchers = req.get("matchers", [])

                async with sem:
                    stats["requests_sent"] += 1
                    try:
                        response = await self.engine.request(
                            method=method, 
                            url=test_url, 
                            headers=headers,
                            allow_redirects=False
                        )
                        
                        if response.get("error"):
                            continue

                        status = response.get("status", 0)
                        body = response.get("body", "")
                        
                        matched = False
                        for matcher in matchers:
                            m_type = matcher.get("type", "")
                            m_condition = matcher.get("condition", "and")
                            
                            # Simple Status Matcher
                            if m_type == "status":
                                expected_statuses = matcher.get("status", [])
                                if status in expected_statuses:
                                    matched = True
                                else:
                                    matched = False
                                    if m_condition == "and": break
                            
                            # Simple Word Matcher
                            elif m_type == "word":
                                expected_words = matcher.get("words", [])
                                word_matched = False
                                for word in expected_words:
                                    if word in body:
                                        word_matched = True
                                        if m_condition == "or": break
                                    else:
                                        if m_condition == "and":
                                            word_matched = False
                                            break
                                            
                                if not word_matched:
                                    matched = False
                                    if m_condition == "and": break
                                else:
                                    matched = True

                        if matched:
                            vuln_info = template.get("info", {})
                            item = {
                                "vuln_id": template.get("id"),
                                "name": vuln_info.get("name", "Unknown"),
                                "severity": vuln_info.get("severity", "info"),
                                "url": test_url
                            }
                            vulns.append(item)
                            stats["vulns_found"] += 1
                            self.logger.success(f"Vulnerability Found: {item['name']} [{item['severity'].upper()}] at {test_url}")
                            
                    except Exception as e:
                        pass
            return vulns

        tasks = [execute_template(t) for t in templates]
        responses = await asyncio.gather(*tasks)

        for r in responses:
            if r:
                results.extend(r)

        return self._make_result(target, results, stats)
