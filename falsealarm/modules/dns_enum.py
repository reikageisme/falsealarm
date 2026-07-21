import asyncio
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.rdatatype
from falsealarm.modules.base import BaseModule, ModuleResult

class DNSEnumModule(BaseModule):
    name = "dns"
    description = "DNS Record Enumeration — Enumerate all DNS records for a domain"
    
    async def run(self, target: str) -> ModuleResult:
        self._start_timer()
        self.logger.module_header(f"DNS Enumeration: {target}")
        
        records = []
        stats = {
            "total_records": 0,
            "record_types_found": [],
            "zone_transfer": False,
            "spf": False,
            "dmarc": False
        }
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.config.timeout
        resolver.lifetime = self.config.timeout
        
        # Async queries mapping
        async def query_record(record_type: str):
            try:
                # Use asyncio.to_thread to make synchronous dns queries async-friendly
                answers = await asyncio.to_thread(resolver.resolve, target, record_type)
                res = []
                for rdata in answers:
                    val = rdata.to_text().strip('"')
                    res.append({"type": record_type, "name": target, "value": val, "ttl": answers.rrset.ttl})
                    
                    if record_type == 'TXT':
                        if val.startswith('v=spf1'):
                            stats["spf"] = True
                return record_type, res
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                return record_type, []
            except Exception as e:
                self.logger.debug(f"Error querying {record_type} for {target}: {e}")
                return record_type, []

        tasks = [query_record(rt) for rt in record_types]
        results = await asyncio.gather(*tasks)
        
        nameservers = []
        for r_type, res in results:
            if res:
                records.extend(res)
                stats["record_types_found"].append(r_type)
                if r_type == 'NS':
                    nameservers.extend([r["value"] for r in res])

        # DMARC
        try:
            dmarc_target = f"_dmarc.{target}"
            dmarc_answers = await asyncio.to_thread(resolver.resolve, dmarc_target, 'TXT')
            for rdata in dmarc_answers:
                val = rdata.to_text().strip('"')
                records.append({"type": "TXT (DMARC)", "name": dmarc_target, "value": val, "ttl": dmarc_answers.rrset.ttl})
                if val.startswith('v=DMARC1'):
                    stats["dmarc"] = True
        except Exception:
            pass

        # DKIM (Common Selectors)
        dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'mail', 's1', 's2']
        async def query_dkim(selector: str):
            dkim_target = f"{selector}._domainkey.{target}"
            try:
                dkim_answers = await asyncio.to_thread(resolver.resolve, dkim_target, 'TXT')
                res = []
                for rdata in dkim_answers:
                    val = rdata.to_text().strip('"')
                    res.append({"type": "TXT (DKIM)", "name": dkim_target, "value": val, "ttl": dkim_answers.rrset.ttl})
                return res
            except Exception:
                return []
        
        dkim_tasks = [query_dkim(s) for s in dkim_selectors]
        dkim_results = await asyncio.gather(*dkim_tasks)
        for res in dkim_results:
            records.extend(res)

        # Zone Transfer (AXFR)
        for ns in nameservers:
            ns_ip = None
            try:
                ns_ans = await asyncio.to_thread(resolver.resolve, ns, 'A')
                ns_ip = ns_ans[0].to_text()
            except Exception:
                continue
            
            if ns_ip:
                try:
                    self.logger.debug(f"Attempting AXFR on {ns} ({ns_ip}) for {target}")
                    z = await asyncio.to_thread(dns.zone.from_xfr, dns.query.xfr(ns_ip, target, timeout=self.config.timeout))
                    for name, node in z.nodes.items():
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                records.append({
                                    "type": dns.rdatatype.to_text(rdataset.rdtype),
                                    "name": f"{name}.{target}" if str(name) != '@' else target,
                                    "value": rdata.to_text(),
                                    "ttl": rdataset.ttl
                                })
                    stats["zone_transfer"] = True
                    self.logger.warning(f"Zone transfer successful on {ns} ({ns_ip})!")
                    break  # Found one, no need to try others
                except Exception as e:
                    self.logger.debug(f"AXFR failed on {ns}: {e}")
        
        stats["total_records"] = len(records)
        
        # Display Table
        if records and not self.config.silent:
            rows = [[r["type"], r["name"], r["value"], str(r["ttl"])] for r in records]
            self.logger.table("DNS Records", ["Type", "Name", "Value", "TTL"], rows)
        
        if not records:
            self.logger.warning("No DNS records found.")
        else:
            self.logger.success(f"Found {len(records)} DNS records.")
        
        return self._make_result(target, records, stats)
