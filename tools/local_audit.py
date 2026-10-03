import os 
import httpx
from dotenv import load_dotenv 
# ------------------------------------------------------------- #

# raw vs rendered settings 
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
# ------------------------------------------------------------- #

# loading the API KEY
load_dotenv()
API_KEY = os.environ.get('GOOGLE_API_KEY')
# ------------------------------------------------------------- #

async def audit_local(query):
    async with httpx.AsyncClient(headers={"User-Agent": BROWSER_UA}, timeout=15) as client:
        payload = {"textQuery": query}
        api_headers = {
            "X-Goog-Api-Key": API_KEY, 
            "X-Goog-FieldMask": "places.rating,places.userRatingCount,places.primaryType,places.googleMapsUri"
        }
        response = await client.post(
            'https://places.googleapis.com/v1/places:searchText',
            json=payload, 
            headers=api_headers
        )
        readable_response = response.json()

    places_list = readable_response.get("places")
    if not places_list:
        return {"error": "Could not find a Google Business Profile for this search."}
    else:
        return places_list[0]
# ------------------------------------------------------------- #

# local scorecard function
def generate_local_scorecard(place_data):
    
    # initializing empty variables
    net_local_score = 0
    action_items = []
    category_scores = {}
   # ------------------------------------------------------------- #

   # rating score 
    if place_data.get("rating", 0.0) >= 4.7:
        net_local_score += 40
        category_scores["average_rating"] = 40
    elif place_data.get("rating", 0.0) >= 4.3:
        net_local_score += 30
        category_scores["average_rating"] = 30
    elif place_data.get("rating", 0.0) >= 4.0:
        net_local_score += 15
        category_scores["average_rating"] = 15
    elif place_data.get("rating", 0.0) < 4.0:
        net_local_score += 0
        category_scores["average_rating"] = 0
        action_items.append("Suggest implementing a feedback loop to address customer complaints.")
    # ------------------------------------------------------------- #

    # evaluating user ratings

    if place_data.get("userRatingCount", 0) >= 100:
        net_local_score += 40
        category_scores["total_reviews"] = 40
    elif place_data.get("userRatingCount", 0) >= 50:
        net_local_score += 30
        category_scores["total_reviews"] = 30
    elif place_data.get("userRatingCount", 0) >= 20:
        net_local_score += 15 
        category_scores["total_reviews"] = 15
    elif place_data.get("userRatingCount", 0) < 20:
        net_local_score += 0
        category_scores["total_reviews"] = 0
        action_items.append("Google Local pack prefers high review velocity.")
    # ------------------------------------------------------------- #

    # evaluate completeness 
    if not place_data.get("primaryType"):
        net_local_score += 0
        category_scores["profile_completeness"] = 0
        action_items.append("Update the primary category of your business to rank for local service searches.")
    else:
        net_local_score += 20
        category_scores["profile_completeness"] = 20

    return {"total_score": net_local_score, "category_scores": category_scores, "recommendations": action_items, "maps_link": place_data.get("googleMapsUri")}
# ------------------------------------------------------------- #

