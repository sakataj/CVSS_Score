import requests
#import pandas as pd
import time
import math
from typing import Tuple

# APIキーを取得したら、以下に記入する
#   取得していない場合 
#     API_KEY = ""
#   取得している場合
#     API_KEY = "12345678-1234-abcd-1234-abcdf0987654"
API_KEY = ""

def get_cvss_score(cve_id:str) -> Tuple[str,float,str,str] :
    '''

        戻り値         
            "CVE_ID": cve_id,
            "baseScore": score,
            "vector":  vector,
            "error":   
    '''
    global highest, API_KEY

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = None
    if (API_KEY != ""):
        headers = {'apiKey':API_KEY}
    
    while True:
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            break       # エラーにならなければループ抜ける
        except Exception as e:
            err_msg = str(e)

            # レート制限にかかったら 再試行する
            if "Too Many Requests" in err_msg:
                # NVD API レート制限により取得失敗 (Too Many Requests)
                print("Too Many Requests により取得失敗。10秒待機して再試行します。")
                time.sleep(10)  # whileに戻る 
            else:
                print(f"エラー: {err_msg}")
                return (cve_id, None, None, err_msg)

    data = resp.json()

    item = data.get("vulnerabilities", [None])[0]
    if not item:
        msg = "データ無し"
        print(msg)
        return (cve_id, None, None, msg)

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
        return (cve_id, None, None, msg)
    
    score = float(score)
    print(f"成功  (score={score})")

    # 最高スコア更新チェック
    if score > highest["baseScore"]:
        highest = {"CVE_ID": cve_id, "baseScore": score, "vector": vector}
        print(f"   → 現在の最高スコアを更新: {cve_id} (score={score})")
    return (cve_id, score, vector, "")




def get_highest_cvss_from_text(cve_text: str, delimiter: str = ','):
    """
    文字列で与えられた複数 CVE から、ベーススコアが最大のものを返す。
    途中経過・エラーも含め詳細をコンソールへ出力する。
    戻り値 : (CVE_ID, baseScore(float), vectorString)  または None
    """
    global highest

    # -------------------------------------------------------------
    # 1) 入力文字列 → リスト化
    # -------------------------------------------------------------
    for ch in ['\n', '\r', '\t', ' ', '、', '，']:
        cve_text = cve_text.replace(ch, delimiter)
    cve_list = [cve.strip() for cve in cve_text.split(delimiter) if cve.strip()]

    if not cve_list:
        print("CVE-ID が検出できませんでした。")
        return None

    print(f"\n取得対象 CVE {len(cve_list)} 件")
    if (API_KEY != ""):
        if len(cve_list) >= 100:
            print(f"※ 100件以上の CVE を指定しています。未登録ユーザーのNVD API のレート制限50req/30secのため、推定所要時間 { math.ceil(len(cve_list) * 6/(60 * 10)) } 分です。")
    else:
        if len(cve_list) >= 10:
            print(f"※ 10件以上の CVE を指定しています。未登録ユーザーのNVD API のレート制限5req/30secのため、推定所要時間 { math.ceil(len(cve_list) * 6/60) } 分です。")

    # -------------------------------------------------------------
    # 2) 各 CVE について NVD API を呼び出し
    # -------------------------------------------------------------
    highest = {"CVE_ID": None, "baseScore": 0.0, "vector": None}
    #records = []

    for idx, cve_id in enumerate(cve_list, 1):

        print(f"[{idx}/{len(cve_list)}] {cve_id} を取得中 … ", end="", flush=True)
        rev = get_cvss_score(cve_id)

        # NVD の API レート制限(5req/30sec)対策
        #  参考 https://nvd.nist.gov/developers/start-here#:~:text=this%20optional%20information.-,Rate%20Limits,-NIST%20firewall%20rules
        if (API_KEY != ""):
            time.sleep(0.6)     # 登録ユーザー 50req/30sec
        else:
            time.sleep(6)       # 未登録ユーザー 5req/30sec



    # -------------------------------------------------------------
    # 3) 最高スコア CVE のサマリー
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
