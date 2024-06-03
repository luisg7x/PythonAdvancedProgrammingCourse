import Numpy as np

response_times = np.array([120, 150, 100, 170, 130, 160, 140, 180, 190, 110])

mean = np.mean (response_times)
print(f"Media: {mean} ms")
#Calcular la mediana
median = np. median (response_times)
print(f"Mediana: {median} ms")
# Calcular la desviación estándar
std_dev = np.std(response_times)
print(f"Desviación estándar: {std_dev}ms")

percentiles = [25, 50, 75, 95]
for percentile in percentiles:
    value = np- percentile(response_times, percentile)
    print(f"Percentil {percentile}: {value} ms")