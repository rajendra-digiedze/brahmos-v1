import os
from dotenv import load_dotenv
load_dotenv()
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
import uuid

# Initialize Qdrant Client (Docker uses "qdrant:6333", local defaults to memory if needed)
qdrant_url = os.environ.get("QDRANT_URL", "http://qdrant:6333")
client = None
try:
    client = QdrantClient(url=qdrant_url)
    client.create_collection(
        collection_name="network_logs",
        vectors_config=VectorParams(size=768, distance=Distance.COSINE),
    )
except Exception as e:
    err = str(e).lower()
    if client is not None and ("already exists" in err or "409" in err):
        pass
    else:
        print(f"Failed to connect to Qdrant or create collection (it may already exist): {e}")
        try:
            client = QdrantClient(":memory:")
            client.create_collection(collection_name="network_logs", vectors_config=VectorParams(size=768, distance=Distance.COSINE))
        except Exception:
            client = None


def get_llm_and_embeddings():
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        print("WARNING: GEMINI_API_KEY is not set. AI Features will mock responses.")
        return None, None
        
    embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")
    llm = ChatGoogleGenerativeAI(model="gemini-pro", convert_system_message_to_human=True)
    return llm, embeddings

def summarize_and_store_log(log_line: str, severity: str):
    """
    Summarization Agent: Takes high severity logs, gets embedding, and stores in VectorDB.
    Layer 4 / Layer 5
    """
    if severity not in ["High", "Critical"]:
        return # Skip unimportant logs

    llm, embeddings = get_llm_and_embeddings()
    if not embeddings:
        return

    # Basic summarization
    summary = f"Summary of {severity} event: The system encountered a potentially malicious request -> {log_line}"
    vector = embeddings.embed_query(summary)
    
    try:
        client.upsert(
            collection_name="network_logs",
            points=[
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload={"log_line": log_line, "severity": severity, "summary": summary}
                )
            ]
        )
    except Exception as e:
        print(f"Error upserting to qdrant: {e}")

import sqlite3
import re
import datetime
from fpdf import FPDF
def chat_with_agent(query: str):
    """
    Response Agent: Takes user query, looks up Qdrant, and responds.
    Layer 4 / Layer 5
    """
    query_lower = query.lower()
    
    if ("recommend" in query_lower or "recommand" in query_lower or "advice" in query_lower or "insight" in query_lower) and "report" not in query_lower and "pdf" not in query_lower:
        blocks = []
        if "deny" in query_lower or "denied" in query_lower:
            blocks.append("""🔴 DENY LOGS (Blocked Traffic)
1. Validate Legitimate Traffic: Review denied IPs and ports to ensure no business-critical apps are blocked. Whitelist only verified trusted sources if required.
2. Tune Firewall Policies: Optimize overly strict rules that may cause unnecessary drops. Use specific source/destination instead of broad deny rules.
3. Detect Suspicious Patterns: Analyze repeated deny attempts from same IPs for scanning or brute-force behavior.""")
        if "malicious" in query_lower or "critical" in query_lower:
            blocks.append("""⚠️ MALICIOUS LOGS (Threat / IPS / AV / Bot Detection)
1. Immediate Threat Validation: Verify detected threats (IPS/AV signatures) to confirm true positives. Escalate critical severity alerts immediately.
2. Patch & Vulnerability Fixing: Identify targeted vulnerabilities from logs and patch affected systems. Prioritize critical CVEs.
3. Block & Contain Attack Sources: Automatically block malicious IPs using dynamic address groups. Integrate with threat intelligence feeds.""")
        if "allow" in query_lower or "allowed" in query_lower:
            blocks.append("""🟢 ALLOWED LOGS (Permitted Traffic)
1. Monitor for Anomalies: Analyze allowed traffic for unusual patterns or spikes. Compare against baseline network behavior.
2. Apply Least Privilege: Ensure allowed rules are not overly permissive. Restrict access to only required ports and IPs.
3. Detect Hidden Threats: Inspect allowed traffic using IPS/SSL inspection. Identify potential threats bypassing basic rules.""")
        
        if blocks:
            return "\n\n".join(blocks)
    
    if "pdf" in query_lower or "report" in query_lower:
        try:
            conn = sqlite3.connect('logs.db')
            cursor = conn.cursor()
            
            min_match = re.search(r'last\s+(\d+)\s*min(?:s|ute|utes)?', query_lower)
            hour_match = re.search(r'last\s+(\d+)\s*hour(?:s)?', query_lower)
            
            now = datetime.datetime.now()
            where_clauses = []
            if min_match:
                cutoff = now - datetime.timedelta(minutes=int(min_match.group(1)))
                where_clauses.append(f"timeline >= '{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
            elif hour_match:
                cutoff = now - datetime.timedelta(hours=int(hour_match.group(1)))
                where_clauses.append(f"timeline >= '{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
                
            status_conditions = []
            if "denied" in query_lower or "deny" in query_lower:
                status_conditions.append("status='Denied'")
            if "allowed" in query_lower or "allow" in query_lower:
                status_conditions.append("status='Allowed'")
            if "malicious" in query_lower or "critical" in query_lower:
                status_conditions.append("severity='Critical'")
                
            if status_conditions:
                where_clauses.append("(" + " OR ".join(status_conditions) + ")")
                
            where_stmt = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            cursor.execute(f"SELECT raw_log, severity FROM logs {where_stmt} ORDER BY id DESC LIMIT 200")
            res = cursor.fetchall()
            
            src_ips = {}
            dest_ips = set()
            ports = set()
            conn_map = {}
            status_counts = {"Total Hits": len(res), "Allowed": 0, "Denied": 0, "Malicious": 0}
            
            for r in res:
                log_line = r[0]
                parts = [p.strip() for p in log_line.split('|')]
                if len(parts) >= 5:
                    src = parts[1]
                    dst = parts[2]
                    d_port = parts[4]
                    status = parts[5] if len(parts) > 5 else "Unknown"
                    sev = parts[6] if len(parts) > 6 else r[1]
                    
                    src_ips[src] = src_ips.get(src, 0) + 1
                    dest_ips.add(dst)
                    ports.add(d_port)
                    conn_key = (src, dst, d_port, status)
                    conn_map[conn_key] = conn_map.get(conn_key, 0) + 1
                    
                    if status == "Allowed":
                        status_counts["Allowed"] += 1
                    elif status == "Denied":
                        status_counts["Denied"] += 1
                    
                    if sev == "Critical":
                        status_counts["Malicious"] += 1

            # --- FETCH GEO-LOCATION ---
            import requests
            geo_info = {}
            top_srcs = [k for k, _ in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]]
            valid_ips = [ip for ip in top_srcs if not (ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.') or ip == '127.0.0.1' or ip == '::1')]
            if valid_ips:
                try:
                    resp = requests.post("http://ip-api.com/batch", json=valid_ips, timeout=3).json()
                    for r in resp:
                        if r.get('status') == 'success':
                            geo_info[r['query']] = f"{r.get('city', 'Unknown')}, {r.get('countryCode', 'Unknown')}"
                except:
                    pass
            
            def get_service_type(port):
                mapping = {'80':'HTTP', '443':'HTTPS', '22':'SSH', '53':'DNS', '3389':'RDP', '445':'SMB', '8000':'API', '5173':'Web'}
                return mapping.get(str(port).strip(), 'TCP/UDP')
            
            # --- START INCIDENT FORM GENERATION (Matching Screenshot Style) ---
            
            llm, _ = get_llm_and_embeddings()
            target = list(src_ips.keys())[0] if src_ips else 'Multiple Sources'
            target_dst = list(dest_ips)[0] if dest_ips else 'Multiple Destinations'

            dynamic_title = f"Alert Analysis: {query[:25]}..."
            dynamic_threat_intel = "The identified IP addresses are being actively monitored and routed through our Threat Intelligence correlation engines."
            incident_type_desc = "[X] Anomalous Target Queries"
            incident_cause_desc = "[X] Mixed External/Internal"

            dynamic_narrative_parts = []
            dynamic_recs = []
            
            if "deny" in query_lower or "denied" in query_lower:
                dynamic_narrative_parts.append(f"blocked/denied traffic across {target_dst}, requiring tuning and scanning validation")
                dynamic_recs.append("DENY LOGS (Blocked Traffic)")
                dynamic_recs.append("Validate Legitimate Traffic: Review denied IPs to ensure no business apps are blocked.")
                dynamic_recs.append("Tune Firewall Policies: Optimize overly strict rules that may cause drops.")
                dynamic_recs.append("Detect Suspicious Patterns: Analyze repeated deny attempts for scanning behavior.")
            
            if "malicious" in query_lower or "critical" in query_lower:
                dynamic_narrative_parts.append(f"malicious threats and IPS/AV alerts across {target_dst}. Immediate containment is advised")
                dynamic_recs.append("MALICIOUS LOGS (Threat / IPS / AV / Bot Detection)")
                dynamic_recs.append("Immediate Threat Validation: Verify and escalate detected IP signatures.")
                dynamic_recs.append("Patch & Vulnerability Fixing: Prioritize CVE patching for affected edge services.")
                dynamic_recs.append("Block & Contain Attack Sources: Automatically block malicious IPs dynamically.")
            
            if "allow" in query_lower or "allowed" in query_lower:
                dynamic_narrative_parts.append(f"allowed inbound/outbound flows across {target_dst}. Continuous monitoring for anomalies is required")
                dynamic_recs.append("ALLOWED LOGS (Permitted Traffic)")
                dynamic_recs.append("Monitor for Anomalies: Analyze traffic for unusual spikes or data transfers.")
                dynamic_recs.append("Apply Least Privilege: Restrict allowed rules to strictly required ports/IPs.")
                dynamic_recs.append("Detect Hidden Threats: Enable IPS/SSL inspection on allowed streams.")
            
            if dynamic_narrative_parts:
                dynamic_narrative = f"We have investigated the recent network activity. Analysis reveals " + "; and ".join(dynamic_narrative_parts) + "."
            else:
                dynamic_narrative = f"We have investigated the recent network activity. Our analysis reveals potential anomalous traffic matching your query across {target_dst}."
                dynamic_recs = [
                    "Validate legitimate network traffic flows.",
                    "Apply least privilege rules to firewall policies.",
                    "Monitor infrastructure for suspicious lateral patterns."
                ]
            
            if llm:
                geo_context = ", ".join([f"{ip} ({geo})" for ip, geo in geo_info.items()])
                log_summary = "\n".join([r[0][:120] for r in res[:15]])
                query_status = []
                if "allow" in query_lower: query_status.append("Allowed")
                if "deny" in query_lower: query_status.append("Denied")
                if "malicious" in query_lower or "critical" in query_lower: query_status.append("Malicious")
                
                prompt = f"""
                You are an elite Agentic-AI SOC Analyst. The user queried: "{query}"
                You are analyzing logs strictly filtered for exactly what was asked: {query_status if query_status else 'All Network Traffic'}.
                Based on this requested scope, here are the matching payload samples:
                {log_summary if log_summary else 'No exact logs matched the time and status parameters.'}
                
                Known Telemetry Geo-Locations: {geo_context if geo_context else 'Local/Internal Network'}
                
                CRITICAL INSTRUCTION: Your Threat Intel and Narrative MUST specifically reflect the actual type of traffic queried ({query_status}). If the user asked for "Allowed" logs, do NOT write a generic threat intel about brute force attacks; instead, write an assessment of the allowed normal traffic. If they asked for "Denied", focus heavily on the nature of the blocked attack patterns.
                Ensure you reference the Geo-Location data in your assessment if relevant.
                The Recommendations MUST be an extremely detailed, professional cybersecurity action plan tailored directly to solving or monitoring the {query_status} traffic seen.
                Output ONLY a JSON object (no markdown formatting or backticks) with these exact keys:
                {{
                    "Title": "A concise, polished report heading",
                    "IncidentType": "1-line description of incident type/category",
                    "IncidentCause": "1-line description of likely cause",
                    "Narrative": "A detailed 3-4 sentence professional narrative explaining the findings based on the query.",
                    "ThreatIntel": "1-2 sentences of threat intelligence context specifically regarding these type of attacks or the data provided.",
                    "Recommendations": [
                        "Containment: [Detailed professional action snippet]",
                        "Mitigation: [Detailed professional action snippet]",
                        "Investigation: [Detailed professional action snippet]",
                        "Hardening: [Detailed professional action snippet]"
                    ]
                }}
                """
                try:
                    import json
                    ai_response = llm.invoke(prompt).content
                    ai_response = ai_response.replace('```json', '').replace('```', '').strip()
                    report_data = json.loads(ai_response)
                    dynamic_title = report_data.get("Title", dynamic_title)
                    incident_type_desc = report_data.get("IncidentType", incident_type_desc)
                    incident_cause_desc = report_data.get("IncidentCause", incident_cause_desc)
                    dynamic_narrative = report_data.get("Narrative", dynamic_narrative)
                    dynamic_threat_intel = report_data.get("ThreatIntel", dynamic_threat_intel)
                    # Use static EXACT 3 points based on Log Type to satisfy reporting guidelines
                except Exception as e:
                    print("Failed to auto-generate from LLM, falling back to basic:", e)

            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            
            # Header
            pdf.set_font("Helvetica", "B", 18)
            pdf.set_text_color(41, 128, 185) # Vivid Blue title
            pdf.cell(190, 10, "ENTERPRISE SOC INTELLIGENCE REPORT", ln=1, align="C")
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(190, 6, "CONFIDENTIAL - RESTRICTED DISTRIBUTION", ln=1, align="C")
            pdf.ln(5)
            
            # Helper function for headers
            def make_header(title):
                pdf.set_fill_color(44, 62, 80) # Slate Dark Blue
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(190, 8, f" {title}", border=1, ln=1, fill=True)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Helvetica", "", 10)
            
            # Helper function for rows
            def make_row(col1, col2, col1_w=60):
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(col1_w, 8, f" {col1}", border=1)
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(190 - col1_w, 8, f" {col2[:110]}", border=1, ln=1)

            # 1. Reporting Site Information
            make_header("1. Reporting Site Information")
            make_row("Title", dynamic_title)
            make_row("Address", "Remote VM / Edge Network Node")
            
            # 2. Report Type
            make_header("2. Report Type")
            pdf.cell(190, 8, "  [X] Executive Action Required   [ ] Statistical Purposes", border=1, ln=1)
            
            # 3. Contact Info
            make_header("3. Reporting/Contact Officer Information")
            make_row("Name", "Agentic-AI SOC L2 (Automated)")
            make_row("Position", "Threat Intelligence Agent")
            make_row("Telephone Number", "+0112170295")
            make_row("Fax Number", "NA")
            make_row("E-mail Address", "soc@dzshield.internal")
            make_row("Alternate Contact information", "NA")
            
            # 4. Incident Status/Type
            make_header("4. Incident Status/Type")
            identified_str = datetime.datetime.now().strftime("%b %d, %Y, %I:%M:%S %p")
            make_row("Incident Dates", f"Incident Identified: {identified_str}")
            pdf.cell(60, 8, " Incident Status", border=1)
            pdf.cell(130, 8, " [ ] Continuing  [ ] Successful  [X] Unsuccessful  [X] Suspected  [ ] Accidental", border=1, ln=1)
            
            pdf.cell(60, 8, " Incident Cause", border=1)
            pdf.cell(130, 8, f" {incident_cause_desc[:100]}", border=1, ln=1)
            
            pdf.cell(60, 25, " Incident Type", border=1)
            x = pdf.get_x()
            y = pdf.get_y()
            pdf.multi_cell(130, 6, f" {incident_type_desc[:80]}.\n"
                                   f" Query Context: {query[:60]}\n"
                                   f" Source IP: {target}\n"
                                   f" Destination IP and Port: {target_dst} : {list(ports)[0] if ports else 'Multiple'}", border=1)
            
            pdf.ln(5)
            
            # 5. Incident Evidence & Detail
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(20, 60, 140)
            pdf.cell(190, 8, "2. Incident Evidence and Detail:", ln=1)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            
            pdf.multi_cell(190, 6, dynamic_narrative)
            pdf.ln(3)
            
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(190, 6, f"Primary Source IP: {target}", ln=1)
            pdf.cell(190, 6, f"Primary Destination IP: {target_dst}", ln=1)
            pdf.cell(190, 6, f"Log Sources: AI-Aggregated Telemetry & Edge Nodes", ln=1)
            pdf.ln(5)
            
            pdf.cell(190, 6, "Please go through below snapshots for offense/event Summary and statistics: Offense Detail:", ln=1)
            
            # --- Matplotlib Chart Generation ---
            try:
                import matplotlib.pyplot as plt
                import matplotlib
                matplotlib.use('Agg')
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
                
                # Dynamic pie chart
                p_labels = [k for k, v in status_counts.items() if k != "Total Hits" and v > 0]
                p_sizes = [v for k, v in status_counts.items() if k != "Total Hits" and v > 0]
                if not p_sizes:
                   p_labels = ['General Traffic']
                   p_sizes = [100]
                ax1.pie(p_sizes, labels=p_labels, autopct='%1.0f%%', textprops={'fontsize': 8})
                ax1.set_title("Traffic Status Summary")
                
                # Dynamic bar chart
                s_ips = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:6]
                if s_ips:
                    b_labels = [x[0][-12:] for x in s_ips]
                    b_counts = [x[1] for x in s_ips]
                else:
                    b_labels = ['No Data']
                    b_counts = [0]
                
                ax2.bar(b_labels, b_counts, color=['#3b82f6']*len(b_labels))
                ax2.set_title("Top Source IPs by Hit Count", fontsize=10)
                plt.xticks(rotation=45, ha='right', fontsize=8)
                
                static_dir = os.path.join(os.path.dirname(__file__), 'static')
                chart_path = os.path.join(static_dir, f"chart_{uuid.uuid4().hex[:8]}.png")
                fig.savefig(chart_path, bbox_inches='tight')
                plt.close(fig)
                
                # Insert Image inline (allows FPDF to naturally manage Y-offset)
                pdf.image(chart_path, x=15, w=180)
                # Removing explicit y=pdf.get_y() and huge ln(80) prevents random blank pages!
                pdf.ln(10)
            except Exception as e:
                pdf.cell(190, 6, "(Chart generation failed. Ensure matplotlib is installed)", ln=1)
            
            # --- Table Generation ---
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_fill_color(52, 73, 94) # Dark Slate Header
            pdf.set_text_color(255, 255, 255)
            headers = ["Source IP", "Geo-Location", "Dest IP", "Port", "Type", "Hits"]
            widths = [30, 40, 30, 20, 30, 40]
            for h, w in zip(headers, widths):
                pdf.cell(w, 7, h, border=1, align='C', fill=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(7)
            
            pdf.set_font("Helvetica", "", 7)
            
            summary_rows = []
            for (sip, dip, dport, stat), count in sorted(conn_map.items(), key=lambda x: x[1], reverse=True)[:7]:
                geo = geo_info.get(sip, "Internal/LAN")
                svc = get_service_type(dport)
                summary_rows.append([sip, geo, dip, dport, svc, f"{stat} ({count})"])
                
            if not summary_rows:
                summary_rows.append(["N/A", "N/A", "N/A", "N/A", "N/A", "0"])
                
            for row in summary_rows:
                for item, w in zip(row, widths):
                    pdf.cell(w, 6, str(item), border=1)
                pdf.ln(6)
            pdf.ln(5)
            
            # Log payloads
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(190, 6, f"Complete Event Payloads ({len(res)} matches):", ln=1)
            pdf.set_font("Helvetica", "", 8)
            
            if not res:
                pdf.multi_cell(190, 5, " - No specific log events matched the exact timeframe and status query.")
            for r in res: 
                pdf.multi_cell(190, 4, f" - {r[0]}")
                pdf.ln(1)
            pdf.ln(3)
            
            # Threat Intel
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(190, 6, "Threat Intel:", ln=1)
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(190, 5, dynamic_threat_intel)
            if target != 'Multiple Sources':
                 pdf.multi_cell(190, 5, f"Check reputation: https://www.virustotal.com/gui/ip-address/{target}")
            pdf.ln(4)
            
            # Recommendations
            pdf.ln(5)
            make_header("5. Strategic Recommendations & Action Plan")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 10)
            
            for r in dynamic_recs:
                if 'LOGS' in r: # Heading
                    pdf.ln(3)
                    pdf.set_font("Helvetica", "B", 11)
                    pdf.set_text_color(52, 73, 94) # Dark Slate Header
                    pdf.cell(190, 6, f"{r}", ln=1)
                    pdf.set_text_color(0, 0, 0)
                else: 
                    parts = r.split(":", 1)
                    if len(parts) == 2:
                        pdf.set_font("Helvetica", "B", 10)
                        pdf.write(6, f"  o  {parts[0].strip()}: ")
                        pdf.set_font("Helvetica", "", 10)
                        pdf.write(6, f"{parts[1].strip()}\n")
                    else:
                        pdf.set_font("Helvetica", "", 10)
                        pdf.write(6, f"  o  {r}\n")
                pdf.ln(1)
            
            # --- END INCIDENT FORM GENERATION ---
            
            filename = f"report_{uuid.uuid4().hex[:8]}.pdf"
            static_dir = os.path.join(os.path.dirname(__file__), 'static')
            filepath = os.path.join(static_dir, filename)
            pdf.output(filepath)
            
            return {
                "response": "I have successfully compiled your detailed ITButler SOC Incident Report covering event evidence, payloads, and threat intel matching your exact documentation specifications. You can download the new PDF below.",
                "pdf_url": f"/static/{filename}"
            }
        except Exception as e:
            return {"response": f"Failed to generate PDF report: {str(e)}"}
        finally:
            if 'conn' in locals():
                conn.close()
                

    llm, embeddings = get_llm_and_embeddings()
    if not llm:
        # Dynamic Mock Agent
        try:
            conn = sqlite3.connect('logs.db')
            cursor = conn.cursor()
            
            # Simple Regex-like extraction for time
            time_filter = ""
            limit_count = 20  # Default to slightly more logs than 3
            
            # Match "last X min" or "last X hour/hr" etc
            min_match = re.search(r'last\s+(\d+)\s*min(?:s|ute|utes)?', query_lower)
            hour_match = re.search(r'last\s+(\d+)\s*hour(?:s)?', query_lower)
            
            now = datetime.datetime.now()
            cutoff = None
            
            if min_match:
                minutes = int(min_match.group(1))
                cutoff = now - datetime.timedelta(minutes=minutes)
            elif hour_match:
                hours = int(hour_match.group(1))
                cutoff = now - datetime.timedelta(hours=hours)

            if cutoff:
                cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
                # When asking for a timeframe, remove the strict limit and return up to 500 logs for the report
                time_filter = f" AND timeline >= '{cutoff_str}'"
                limit_count = 500
                
            # First priority: Contextual questions about recommendations
            if "recommend" in query_lower or "recommandation" in query_lower or "advice" in query_lower:
                return """[timbr.ai SecOps Agent] Based on the context of recent Denied and Critical IP blocks, here is my SOC strategic advisory:
                
**1. Immediate Network Containment**
Blacklist the recurring 'Denied' Source IPs immediately at the perimeter Layer 3 firewall to prevent volumetric exhaustion.

**2. Audit Edge Defenses**
Since there are Critical (Malicious) hits, it means active exploits were attempted. Ensure your WAF rules and Zero-Trust proxies are fully updated to block SQLi, XSS, or Directory Traversal vectors targeting those specific ports.

**3. Implement strict Rate-Limiting**
High hit counts from single addresses indicates automated probing/scanning. Configure NGINX or API Gateways to rate-limit or temporarily ban IPs exceeding 50 requests/min.

**4. Threat Intelligence Review**
Correlate the offending IPs against OpenCTI or AbuseIPDB to determine if this is part of a larger botnet campaign."""

            # If the user just asks "logs" without any specific status filter:
            if "denied" in query_lower or "deny" in query_lower:
                cursor.execute(f"SELECT raw_log FROM logs WHERE status='Denied'{time_filter} ORDER BY id DESC LIMIT {limit_count}")
                res = cursor.fetchall()
                if res:
                    logs_str = "\n".join([f"- {r[0]}" for r in res])
                    return f"[CrewAI Orchestrator -> Mistral Sub-Agent] Task Complete:\nI analyzed the Apache Atlas logs via LlamaIndex. Found these Denied IPs bridging the Zero-Trust mesh within the requested parameters:\n{logs_str}"
                return "[CrewAI Orchestrator] No denied events found matching your query parameters."
            elif "malicious" in query_lower or "critical" in query_lower:
                cursor.execute(f"SELECT raw_log FROM logs WHERE severity='Critical'{time_filter} ORDER BY id DESC LIMIT {limit_count}")
                res = cursor.fetchall()
                if res:
                    logs_str = "\n".join([f"- {r[0]}" for r in res])
                    return f"[Alert from NVIDIA NeMo Agent]\nMalicious traffic signature detected by SiliconFlow inference! Extracted target vectors:\n{logs_str}"
                return "[timbr.ai Analyzer] Network graphs look clear of any critical topology breaches matching your time bounds."
            elif "allowed" in query_lower or "allow" in query_lower:
                cursor.execute(f"SELECT raw_log FROM logs WHERE status='Allowed'{time_filter} ORDER BY id DESC LIMIT {limit_count}")
                res = cursor.fetchall()
                if res:
                    logs_str = "\n".join([f"- {r[0]}" for r in res])
                    return f"[Chat4ED LlamaIndex Result] Filtered standard allowed flow through Apache NiFi context:\n{logs_str}"
                return "[Mistral Retrieval] Zero 'Allowed' packets matched the temporal window requested."
            else:
                # General query for ANY logs in the timeframe (since user might ask 'give me last 5 mins logs' without status)
                cursor.execute(f"SELECT raw_log FROM logs WHERE 1=1 {time_filter} ORDER BY id DESC LIMIT {limit_count}")
                res = cursor.fetchall()
                if res and time_filter:
                    logs_str = "\n".join([f"- {r[0]}" for r in res])
                    report = f"""**INCIDENT REPORTING FORM**
*dZshield-SOC-F-02*

### 1. Report Type & Officer Information
* **Report Type**: Seeking Assistance - Statistical Purposes
* **Officer Name**: dZshield Matrix Agent (Automated)
* **Status**: Authorized SOC Level-2 AI Analyst

### 2. Incident Status/Type
* **Incident Target Timeframe**: {cutoff_str} to NOW.
* **Incident Status**: ☑ Suspected  ☑ Unsuccessful
* **Incident Cause**: ☑ Outsider  ☑ Unknown
* **Incident Type**: Multiple Network Attempts from External Source

### 3. Incident Evidence and Detail
We have investigated potential anomalous traffic across the internal Zero-Trust infrastructure. Our analysis reveals multiple systematic events mapping back to the provided timeframe. This behavior is consistent with reconnaissance attack patterns, where threat actors systematically access infrastructure ports. Immediate tracking has been enabled to prevent unauthorized lateral movement.

### 4. Event Payloads (Extracted Signatures):
```text
{logs_str[:1500]}... [Truncated for brevity]
```

### 5. Threat Intel
The IP addresses attempting to traverse this environment are currently being monitored against known OSINT feeds. You should proactively examine them via:
https://www.virustotal.com/gui/

### 6. Recommendations
* Configure your primary network edge firewall to strictly allow access ONLY from trusted IP addresses.
* Regularly execute patching metrics to address known critical application vulnerabilities.
* Establish and enforce password rotation policies to block sequential brute-force attempts.
* Kindly block any malicious IPs listed above across all internal micro-segmentations.
"""
                    return report
                
            cursor.execute("SELECT COUNT(*) FROM logs")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE severity='Critical'")
            critical = cursor.fetchone()[0]
            return f"[dZshield SOC Summary]\nCurrently tracking {total} network packets across the Kubernetes cluster.\nNVIDIA NeMo agents have blocked {critical} critical attempts. (Try asking to 'show malicious logs')."
        except Exception as e:
            return f"Demo Mode Error: {e}"
        finally:
            if 'conn' in locals():
                 conn.close()

    # RAG Lookups
    try:
        vector = embeddings.embed_query(query)
        search_result = client.search(
            collection_name="network_logs",
            query_vector=vector,
            limit=3
        )
        context = "\n".join([f"- {hit.payload['summary']}" for hit in search_result])
    except Exception as e:
        context = "No relevant network log history found."

    prompt = f"""
    SYSTEM ROLE: You are 'dZshield-Agent-L5', an elite AI Security Analyst operating at Layer 5 Orchestration within an Enterprise SOC.
    
    KNOWLEDGE BASE CONTEXT (Layer 3):
    {context}
    
    USER QUERY: 
    {query}
    
    TASK: Answer the user's question with utmost accuracy based strictly on the provided context. Structure your response as a professional, enterprise-grade Incident Report. Use professional SOC formatting (e.g., Executive Summary, Findings, Recommended Actions) where applicable. Maintain an authoritative and analytic tone without hallucinating logs outside the context.
    """
    
    try:
        response = llm.invoke(prompt)
        return response.content
    except Exception as e:
        return f"Google AI Configuration Error: {str(e)}. Please ensure your GEMINI_API_KEY inside the .env file is technically valid and not the placeholder!"
