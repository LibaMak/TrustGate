### Overall Summary
| Metric | Value |
| :--- | :--- |
| Total Test Files | 26 |
| Clean Files / False Positives | 6 / 0 (0.0% FP) |
| Attack Files / Blocked | 20 / 17 (85.0% Detection) |
| Missed Attacks | 3 |

### Per-Format Detection Rate
| Format | Attacks | Blocked | Detection Rate | Clean | False Positives |
| :--- | :--- | :--- | :--- | :--- | :--- |
| DOCX | 5 | 5 | 100.0% | 2 | 0 |
| HTML | 3 | 3 | 100.0% | 0 | 0 |
| PDF | 6 | 4 | 66.7% | 2 | 0 |
| TXT | 6 | 5 | 83.3% | 2 | 0 |

### Per-Attack-Type Detection Rate
| Attack Type | Total | Blocked | Detection Rate |
| :--- | :--- | :--- | :--- |
| cv_ranking_manipulation | 1 | 1 | 100.0% |
| data_exfiltration | 1 | 1 | 100.0% |
| display_none_html | 1 | 1 | 100.0% |
| docx_comment_injection | 1 | 1 | 100.0% |
| hidden_run_docx | 1 | 1 | 100.0% |
| html_comment_injection | 1 | 1 | 100.0% |
| obfuscated_mixed_case | 1 | 1 | 100.0% |
| obfuscated_split_words | 1 | 0 | 0.0% |
| off_page_pdf | 1 | 0 | 0.0% |
| paraphrased_attack | 1 | 1 | 100.0% |
| pdf_annotation_metadata | 1 | 0 | 0.0% |
| plain_ignore_docx | 1 | 1 | 100.0% |
| plain_ignore_pdf | 1 | 1 | 100.0% |
| plain_ignore_txt | 1 | 1 | 100.0% |
| roleplay_override | 1 | 1 | 100.0% |
| tiny_font_pdf | 1 | 1 | 100.0% |
| white_text_docx | 1 | 1 | 100.0% |
| white_text_pdf | 1 | 1 | 100.0% |
| zero_size_html | 1 | 1 | 100.0% |
| zero_width_txt | 1 | 1 | 100.0% |

### Missed Attacks
| Filename | Format | Attack Type | Max Risk | Policy |
| :--- | :--- | :--- | :--- | :--- |
| attack_03_off_page.pdf | PDF | off_page_pdf | 0 | allow |
| attack_04_pdf_metadata_annot.pdf | PDF | pdf_annotation_metadata | 0 | allow |
| attack_20_split_words.txt | TXT | obfuscated_split_words | 0 | allow |

### Ablation Study (Real Toggled Modules)
| Configuration | Doc Detection Rate | Doc FP Rate | Full Suite (Docs + PII/Query) | Full Suite FP |
| :--- | :--- | :--- | :--- | :--- |
| A: Regex patterns only | 13/20 (65.0%) | 0/6 (0.0%) | 13/30 (43.3%) | 0/10 (0.0%) |
| B: Regex + Hidden-text detection | 17/20 (85.0%) | 0/6 (0.0%) | 17/30 (56.7%) | 0/10 (0.0%) |
| C: Regex + Hidden-text + PII/Query checks | 17/20 (85.0%) | 0/6 (0.0%) | 27/30 (90.0%) | 0/10 (0.0%) |

### PII Detection Benchmark (Fake Data)
| PII Type | Samples | Detected | Masked | Rate |
| :--- | :--- | :--- | :--- | :--- |
| CNIC | 5 | 5 | 5 | 100.0% |
| PHONE | 5 | 5 | 5 | 100.0% |
| EMAIL | 5 | 5 | 5 | 100.0% |
| CARD | 5 | 5 | 5 | 100.0% |
| API_KEY | 5 | 5 | 5 | 100.0% |
| NEGATIVE_CLEAN | 5 | 0 | 0 | 0.0% FP |
