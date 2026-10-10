from django.http import JsonResponse

from introduction.playground.A6.utility import check_vuln

from .playground_review import (CodeReviewError, review_dependency_checker, review_logging_exercise,
                                review_ssrf_fix)
from .utility import ssrf_html_input_extractor
from .views import authentication_decorator

# Coding playgrounds.
# Learner code is reviewed as DATA (introduction/playground_review.py): it is parsed with
# ast.parse() and inspected, never written to a .py file, imported or executed. The previous
# version wrote it into modules imported by the application (persistent code injection, CWE-94).
# All endpoints require an authenticated user and Django's CSRF protection (the pages send
# the X-CSRFToken header).


def ssrf_code_checker(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            python_code = request.POST.get('python_code', '')
            html_code = request.POST.get('html_code', '')
            try:
                result = review_ssrf_fix(python_code, ssrf_html_input_extractor(html_code))
            except CodeReviewError as exc:
                return JsonResponse({"status": "error", "message": f"Invalid code: {exc}"})
            if result["passed"]:
                return JsonResponse({'message': result["message"], 'passed': 1}, status=200)
            return JsonResponse({'message': result["message"]}, status=200)
        else:
            return JsonResponse({'message':'method not allowed'},status = 405)
    else:
        return JsonResponse({'message':'UnAuthenticated User'},status = 401)

# Insufficient Logging & Monitoring
@authentication_decorator
def log_function_checker(request):
    if request.method == 'POST':
        try:
            result = review_logging_exercise(request.POST.get('log_code', ''), request.POST.get('api_code', ''))
        except CodeReviewError as exc:
            return JsonResponse({"message": "failure", "logs": [str(exc)]}, status=400)
        return JsonResponse({"message": "success", "logs": result["logs"], "passed": result["passed"]}, status=200)
    else:
        return JsonResponse({"message":"method not allowed"},status = 405)

#a7 codechecking api
@authentication_decorator
def A7_disscussion_api(request):
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)

    code = request.POST.get('code')
    if code is None:
        return JsonResponse({"message":"missing code"},status = 400)

    search_snipet = "AF_session_id.objects.get(sesssion_id = cookie).delete()"
    search_snipet2 = "AF_session_id.objects.get(sesssion_id=cookie).delete()"

    if (search_snipet in code) or (search_snipet2 in code):
        return JsonResponse({"message":"success"},status = 200)

    return JsonResponse({"message":"failure"},status = 400)

#a6 codechecking api
@authentication_decorator
def A6_disscussion_api(request):
    # "Run code": the vulnerability data comes from the trusted reference implementation
    # (playground/A6/utility.py, never modified at runtime); the learner code is reviewed statically.
    test_bench = ["Pillow==8.0.0","PyJWT==2.4.0","requests==2.28.0","Django==4.0.4"]
    review = None
    if request.POST.get('code'):
        try:
            review = review_dependency_checker(request.POST['code'])["feedback"]
        except CodeReviewError as exc:
            review = [str(exc)]
    try:
        result = check_vuln(test_bench)
        if result:
            return JsonResponse({"message":"success","vulns":result, "review": review},status = 200)
        return JsonResponse({"message":"failure", "review": review},status = 400)
    except Exception:
        return JsonResponse({"message":"failure", "review": review},status = 400)

@authentication_decorator
def A6_disscussion_api_2(request):
    # "Save code": the code is reviewed and the feedback returned; nothing is written to disk.
    if request.method != 'POST':
        return JsonResponse({"message":"method not allowed"},status = 405)
    try:
        result = review_dependency_checker(request.POST.get('code', ''))
    except CodeReviewError as exc:
        return JsonResponse({"message": "failure", "feedback": [str(exc)]}, status=400)
    return JsonResponse({"message": "success", "passed": result["passed"], "feedback": result["feedback"]},
                        status=200)
