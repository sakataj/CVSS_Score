import requests
import pandas as pd
import time

def get_highest_cvss_from_text(cve_text: str, delimiter: str = ','):
    """
    文字列で与えられた複数 CVE から、ベーススコアが最大のものを返す。
    途中経過・エラーも含め詳細をコンソールへ出力する。
    戻り値 : (CVE_ID, baseScore(float), vectorString)  または None
    """

    # -------------------------------------------------------------
    # 1) 入力文字列 → リスト化
    # -------------------------------------------------------------
    for ch in ['\n', '\r', '\t', ' ', '、', '，']:
        cve_text = cve_text.replace(ch, delimiter)
    cve_list = [cve.strip() for cve in cve_text.split(delimiter) if cve.strip()]

    if not cve_list:
        print("CVE-ID が検出できませんでした。")
        return None

    print(f"\n取得対象 CVE ({len(cve_list)} 件): {', '.join(cve_list)}\n")

    # -------------------------------------------------------------
    # 2) 各 CVE について NVD API を呼び出し
    # -------------------------------------------------------------
    highest = {"CVE_ID": None, "baseScore": -1.0, "vector": None}
    records = []

    for idx, cve_id in enumerate(cve_list, 1):
        print(f"[{idx}/{len(cve_list)}] {cve_id} を取得中 … ", end="", flush=True)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            item = data.get("vulnerabilities", [None])[0]
            if not item:
                msg = "データ無し"
                print(msg)
                records.append({
                    "CVE_ID": cve_id,
                    "baseScore": None,
                    "vector":  None,
                    "error":    msg
                })
                continue

            metrics = item["cve"].get("metrics", {})
            score = vector = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    entry = next(
                        (e for e in metrics[key] if e.get("type") == "Primary"),
                        metrics[key][0]
                    )
                    cvss = entry["cvssData"]
                    score  = cvss.get("baseScore")
                    vector = cvss.get("vectorString")
                    break

            if score is None:
                msg = "スコア取得失敗 (metrics 無し)"
                print(msg)
                records.append({
                    "CVE_ID": cve_id,
                    "baseScore": None,
                    "vector":  None,
                    "error":    msg
                })
                continue

            score = float(score)
            records.append({
                "CVE_ID": cve_id,
                "baseScore": score,
                "vector":  vector,
                "error":   ""
            })
            print(f"成功  (score={score})")

            # 最高スコア更新チェック
            if score > highest["baseScore"]:
                highest = {"CVE_ID": cve_id, "baseScore": score, "vector": vector}
                print(f"   → 現在の最高スコアを更新: {cve_id} (score={score})")

        except Exception as e:
            err_msg = str(e)
            print(f"エラー: {err_msg}")
            records.append({
                "CVE_ID": cve_id,
                "baseScore": None,
                "vector":  None,
                "error":    err_msg
            })

        # NVD の無料 API レート制限(60 req/min)対策
        time.sleep(1)

    # -------------------------------------------------------------
    # 3) 取得結果を一覧表示（エラーのみ）
    # -------------------------------------------------------------
    df = pd.DataFrame(records)

    # error 列が空でない（= 失敗した）行だけ抽出
    df_err = df[df["error"] != ""]

    print("\n===== 取得失敗 CVE 一覧 =====")
    if df_err.empty:
        print("すべての CVE でスコア取得に成功しました。")
    else:
        # NaN を空文字列にして見やすく
        print(df_err.fillna("").to_string(index=False))

    # -------------------------------------------------------------
    # 4) 最高スコア CVE のサマリー
    # -------------------------------------------------------------
    if highest["CVE_ID"] is None:
        print("\n有効な CVE スコアを取得できませんでした。")
        return None

    print("\n===== 最高スコア CVE =====")
    print(f"CVE-ID        : {highest['CVE_ID']}")
    print(f"BaseScore     : {highest['baseScore']}")
    print(f"VectorString  : {highest['vector']}")
    return highest["CVE_ID"], highest["baseScore"], highest["vector"]


# -------------------------------------------------------------
# メイン処理（ユーザ入力）
# -------------------------------------------------------------
if __name__ == "__main__":
    print("CVE-ID を入力してください：")
    user_cve_text = ""
    while not user_cve_text.strip():
        user_cve_text = input("> ").strip()


    get_highest_cvss_from_text(user_cve_text)
