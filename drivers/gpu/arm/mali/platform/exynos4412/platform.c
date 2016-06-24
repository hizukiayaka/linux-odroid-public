/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * This program is free software and is provided to you under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
 *
 * A copy of the licence is included with the program, and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/version.h>
#include "mali_kernel_common.h"
#include "mali_kernel_linux.h"
#include "mali_osk.h"
#include "mali_osk_mali.h"

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/driver.h>
#include <linux/mali/mali_utgard.h>
#include <linux/dma-contiguous.h>
#include <linux/cma.h>
#include <linux/delay.h>

static struct clk *sclk_g3d_clock = NULL;
static struct clk *g3d_clock = NULL;
static struct regulator *g3d_regulator = NULL;


static void exynos4412_utilization_callback(struct mali_gpu_utilization_data *data)
{
	printk("DEBUG: Mali GPU utilization: GPU = %u, GP = %u, PP = %u\n",
		data->utilization_gpu, data->utilization_gp, data->utilization_pp);
}

static int exynos4412_clk_enable(struct platform_device *device)
{
	struct device *dev = &device->dev;
	unsigned long rate;

	sclk_g3d_clock = clk_get(dev, "sclk_g3d");
	if (IS_ERR(sclk_g3d_clock)) {
		MALI_PRINT_ERROR(("Mali platform: failed to get source g3d clock\n"));
		goto fail_sclk;
	}

	g3d_clock = clk_get(dev, "g3d");
	if (IS_ERR(g3d_clock)) {
		MALI_PRINT_ERROR(("Mali platform: failed to get g3d clock\n"));
		goto fail_g3d;
	}

	if (clk_prepare_enable(sclk_g3d_clock) < 0) {
		MALI_PRINT_ERROR(("Mali platform: failed to enable source g3d clock\n"));
		goto fail_enable_sclk;
	}

	if (clk_prepare_enable(g3d_clock) < 0) {
		MALI_PRINT_ERROR(("Mali platform: failed to enable g3d clock\n"));
		goto fail_enable_g3d;
	}

	rate = clk_get_rate(sclk_g3d_clock);

	MALI_PRINT(("Mali platform: source g3d clock rate = %u MHz\n", rate / 1000000));

	rate = clk_get_rate(g3d_clock);

	MALI_PRINT(("Mali platform: g3d clock rate = %u MHz\n", rate / 1000000));

	return 0;

fail_enable_g3d:
	clk_disable_unprepare(sclk_g3d_clock);

fail_enable_sclk:
	clk_put(g3d_clock);

fail_g3d:
	g3d_clock = NULL;
	clk_put(sclk_g3d_clock);

fail_sclk:
	sclk_g3d_clock = NULL;
	return -EFAULT;
}

static void exynos4412_clk_disable(void)
{
	if (g3d_clock) {
		clk_disable_unprepare(g3d_clock);
		clk_put(g3d_clock);
		g3d_clock = NULL;
	}

	if (sclk_g3d_clock) {
		clk_disable_unprepare(sclk_g3d_clock);
		clk_put(sclk_g3d_clock);
		sclk_g3d_clock = NULL;
	}
}

#ifdef CONFIG_REGULATOR
static int exynos4412_set_voltage(int min_uV, int max_uV)
{
	int voltage;

	MALI_DEBUG_PRINT(3, ("Mali platform: setting g3d regulator to: %d / %d uV\n", min_uV, max_uV));
	regulator_set_voltage(g3d_regulator, min_uV, max_uV);

	voltage = regulator_get_voltage(g3d_regulator);
	MALI_DEBUG_PRINT(3, ("Mali platform: g3d regulator set to: %d uV\n", voltage));

	return 0;
}

static int exynos4412_regulator_reset(struct platform_device *device)
{
	if (regulator_disable(g3d_regulator))
		goto err;

	usleep_range(4000, 10000);

	if (regulator_enable(g3d_regulator))
		goto err;

	return 0;

err:
	MALI_PRINT_ERROR(("Mali platform: failed to reset g3d regulator\n"));
	return -EFAULT;
}

static int exynos4412_regulator_enable(struct platform_device *device)
{
	/*
	 * Be careful when lowering this value (it can cause system stability
	 * issues like kernel Oopses and lockups).
	 */
	const unsigned int default_gpu_vol = 1125000; /* 1.1125 V */

	struct device *dev = &device->dev;
	g3d_regulator = regulator_get(dev, "gpu");

	if (IS_ERR(g3d_regulator)) {
		MALI_PRINT_ERROR(("Mali platform: failed to get g3d regulator\n"));
		goto fail_get;
	}

	if (regulator_enable(g3d_regulator)) {
		MALI_PRINT_ERROR(("Mali platform: failed to enable g3d regulator\n"));
		goto fail_enable;
	}
	MALI_DEBUG_PRINT(3, ("Mali platform: g3d regulator enabled\n"));

	if (exynos4412_set_voltage(default_gpu_vol, default_gpu_vol)) {
		goto fail_set;
	}

	return 0;

fail_set:
	regulator_disable(g3d_regulator);

fail_enable:
	regulator_put(g3d_regulator);

fail_get:
	g3d_regulator = NULL;
	return -EFAULT;
}

static void exynos4412_regulator_disable(void)
{
	if (!g3d_regulator)
		return;

	regulator_disable(g3d_regulator);
	regulator_put(g3d_regulator);
	g3d_regulator = NULL;
}
#else
static int exynos4412_regulator_reset(struct platform_device *device) { return 0; }
static int exynos4412_regulator_enable(struct platform_device *device) { return 0; }
static void exynos4412_regulator_disable() {}
#endif

int mali_platform_device_init(struct platform_device *device)
{
	int ret;
	struct mali_gpu_device_data mali_gpu_data = { 0 };

	struct cma *default_area = dma_contiguous_default_area;

	ret = exynos4412_regulator_enable(device);
	if (ret < 0)
		goto fail_regulator;

	ret = exynos4412_regulator_reset(device);
	if (ret < 0)
		goto fail_reset;

	ret = exynos4412_clk_enable(device);
	if (ret < 0)
		goto fail_clk;

	if (default_area) {
		mali_gpu_data.fb_start = cma_get_base(default_area);
		mali_gpu_data.fb_size = cma_get_size(default_area);
	}

	mali_gpu_data.control_interval = 1000; /* 1000 ms */
	mali_gpu_data.utilization_callback = exynos4412_utilization_callback;

#if 0
	mali_gpu_data.set_freq = NULL;
	mali_gpu_data.get_clock_info = NULL;
	mali_gpu_data.get_freq = NULL;
#endif

	ret = platform_device_add_data(device, &mali_gpu_data, sizeof(mali_gpu_data));
	if (ret < 0)
		goto fail_platform_data;

#ifdef CONFIG_PM
	pm_runtime_set_autosuspend_delay(&(device->dev), 1000);
	pm_runtime_use_autosuspend(&(device->dev));
	pm_runtime_enable(&(device->dev));
#endif

	return 0;

fail_platform_data:
	exynos4412_clk_disable();

fail_reset:
fail_clk:
	exynos4412_regulator_disable();

fail_regulator:
	return ret;
}

int mali_platform_device_deinit(struct platform_device *device)
{
#ifdef CONFIG_PM
	pm_runtime_disable(&device->dev);
#endif

	exynos4412_clk_disable();
	exynos4412_regulator_disable();

	MALI_DEBUG_PRINT(4, ("Mali platform: finished deinit\n"));

	return 0;
}
